package spf

import (
  "testing"

  "github.com/stretchr/testify/assert"
)

func gdfe(t *testing.T, expected, eml string) {
  e, err := GetDomainFromEmail(eml)
  if err != nil {
    t.Error(err)
  }
  assert.Equal(t, expected, e)
}

func TestEmailParsing(t *testing.T) {
  gdfe(t, "garvey.me", "cathal@garvey.me")
  gdfe(t, "garvey.me", "Cathal <cathal@garvey.me>")
  gdfe(t, "garvey.me", "Cathal <cathalGarvey@garvey.me>")
  gdfe(t, "garvey.me", "cathal@Garvey.Me")
}

func TestSPFRecords(t *testing.T) {
  ip := "93.95.224.70"  // mail.1984.is
  // vulpinedesigns.co.uk has an SPF record set
  ok, err := Validate(ip, "vulpinedesigns.co.uk")
  assert.Nil(t, err)
  assert.False(t, ok)
  // cathalgarvey.me has no SPF record set
  ok, err = Validate(ip, "cathalgarvey.me")
  assert.Nil(t, err)
  assert.True(t, ok)
}
