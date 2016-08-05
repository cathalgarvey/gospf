package spf

import (
	"errors"
	"net"
	"net/mail"
	"strings"
)

var (
	// ErrNoSPFRecords when no TXT/SPF records are found or parsed.
	ErrNoSPFRecords = errors.New("No SPF Records found.")

	looker *spfChecker
)

func init() {
	looker = NewSPFChecker()
}

// Validate returns whether emails from a domain can be sent from a given IP.
// This is the intended main entry point to this library.
// If you have an email address, then use GetDomainFromEmail to get the domain.
// Results from Validate are simply cached in RAM; extended and heavy use may
// create a memory leak. If this is a problem, simply call the top-level
// DumpCache function.
func Validate(ip, domain string) (bool, error) {
	return looker.Validate(ip, domain)
}

// DumpCache dumps the cache from the built-in SPF Checker.
func DumpCache() {
	looker.DumpCache()
}

// spfChecker is a cached TXT looker-upper and SPF checker
type spfChecker struct {
	Cache map[string][]string
}

// NewSPFChecker returns a SPF looker-upper with an internal cache.
// You should probably use the library's instance through the top-level functions.
func NewSPFChecker() *spfChecker {
	s := new(spfChecker)
	s.Cache = make(map[string][]string)
	return s
}

// DumpCache resets the SPF cache to an empty map.
func (sc *spfChecker) DumpCache() {
	sc.Cache = make(map[string][]string)
}

// LookupSPFRecords is a cached lookup for SPF records
func (sc *spfChecker) LookupSPFRecords(domain string) ([]string, error) {
	_, ok := sc.Cache[domain]
	if !ok {
		txtRecords, err := net.LookupTXT(domain)
		if err != nil {
			return nil, err
		}
		if txtRecords == nil || len(txtRecords) == 0 {
			return nil, ErrNoSPFRecords
		}
		spfRs, err := findSPFRecord(txtRecords)
		if err != nil {
			return nil, err
		}
		if spfRs == nil || len(spfRs) == 0 {
			return nil, ErrNoSPFRecords
		}
		sc.Cache[domain] = spfRs
	}
	return sc.Cache[domain], nil
}

// Validate returns whether an IP is allowed to post from a given domain
func (sc *spfChecker) Validate(ip, domain string) (bool, error) {
	spfRecordList, err := sc.LookupSPFRecords(domain)
	if err != nil {
		if err == ErrNoSPFRecords {
			return false, nil
		}
		return false, err
	}
	spfRecord := spfRecordList[0]
	splitSPFRecord := strings.Split(spfRecord, " ")
	allRecord := splitSPFRecord[len(splitSPFRecord)-1]
	allRecordSplit := strings.Split(allRecord, "a")
	allRecord = allRecordSplit[0]

	ips, err := getIPsForRecord(domain, spfRecord)
	if err != nil {
		return false, err
	}

  // TODO Does this need IPv6 modernisation? Not clear what's happening with the
	// mask suffixing.
	for _, element := range ips {
		elementWithCidr := element
		if !strings.Contains(elementWithCidr, "/") {
			if !strings.Contains(elementWithCidr, ":") {
				elementWithCidr = elementWithCidr + "/32" // fmt.Sprintf("%s/32", elementWithCidr)
			} else {
				elementWithCidr = elementWithCidr + "/128" // fmt.Sprintf("%s/128", elementWithCidr)
			}
		}
		_, cidrnet, err := net.ParseCIDR(elementWithCidr)
		if err != nil {
			return false, err
		}
		ipAddress := net.ParseIP(ip)
		if cidrnet.Contains(ipAddress) {
			return true, nil
		}
	}
	return false, nil
}

// GetDomainFromEmail returns the domain name from an email address. It is
// somewhat naive at present.
func GetDomainFromEmail(email string) (string, error) {
	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return "", err
	}
	return processEmail(strings.ToLower(strings.TrimSpace(parsed.Address)))
}

// == Everything Under Here Unmodified from Original ==

//Splits an email address into "username" and "domain" parts. It gives back the domain name.
func processEmail(email string) (string, error) {
	splitEmail := strings.Split(email, "@")
	if len(splitEmail) != 2 {
		return "", errors.New("Email address either has not enough or too many @ symbols")
	}
	domain := splitEmail[1]
	return domain, nil
}

//Locates the SPF record in the txt records, and returns the record as long as there aren't too many.
func findSPFRecord(txtRecords []string) ([]string, error) {
	var spfRecords []string
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			spfRecords = append(spfRecords, record)
		}
	}
	if len(spfRecords) == 0 || len(spfRecords) > 1 {
		return []string{}, errors.New("Too many SPF records found")
	}
	return spfRecords, nil
}

func getIPsForRecord(domain string, record string) ([]string, error) {
	var spfSections []string
	var cidrIPs []string
	splitTextRecords := strings.Split(record, " ")
	for _, element := range splitTextRecords {
		spfSections = append(spfSections, element)
	}
	for _, element := range spfSections {
		if strings.HasPrefix("v=spf1", element) {
			continue
		} else if strings.HasPrefix(element, "ip4") {
			cidr := strings.Replace(element, "ip4:", "", -1)
			cidrIPs = append(cidrIPs, cidr)
			continue
		} else if strings.HasPrefix(element, "include") {
			record := strings.Replace(element, "include:", "", -1)
			txtRecords, err := net.LookupTXT(record)
			if err != nil {
				return []string{}, err
			}
			spfRecordList, err := findSPFRecord(txtRecords)
			if err != nil {
				return []string{}, err
			}
			spfRecord := spfRecordList[0]
			recursiveList, err := getIPsForRecord(record, spfRecord)
			for _, element := range recursiveList {
				cidrIPs = append(cidrIPs, element)
			}
			continue
		} else if strings.ToLower(element) == "a" || strings.ToLower(element) == "mx" {
			otherRecord, err := parseOtherRecord(domain, element)
			if err != nil {
				return []string{}, err
			}
			for _, element := range otherRecord {
				cidrIPs = append(cidrIPs, element)
			}
			continue
		} else {
			continue
		}
	}
	return cidrIPs, nil
}

func parseOtherRecord(domain string, record string) ([]string, error) {
	var ipList []string
	if record == "a" {
		ip, err := net.LookupIP(domain)
		if err != nil {
			return []string{}, err
		}
		for _, element := range ip {
			ipList = append(ipList, element.String())
		}
		return ipList, nil
	} else if record == "mx" {
		ip, err := net.LookupMX(domain)
		if err != nil {
			return []string{}, err
		}
		for _, element := range ip {
			MXARecords, err := parseOtherRecord(element.Host, "a")
			if err != nil {
				return []string{}, err
			}
			for _, listElement := range MXARecords {
				ipList = append(ipList, listElement)
			}

		}
		return ipList, nil
	}
	return []string{}, errors.New("Unknown Record for SPF")
}
