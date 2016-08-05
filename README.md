Borrowed and refactored from [daniellockard/gospfquery](https://github.com/daniellockard/gospfquery),
to remove log.Fatal calls and make it more library-ish.

As explained in [daniellockard](https://github.com/daniellockard)'s original Readme:

This does not implement REDIRECT, PTR, or EXISTS. The checking for the "ALL" record is very rough.
It also turns all IPv6 records that lack a hostmask into a /128, because I don't know anything about IPv6 addresses.
It turns IP4: records without a hostmask into a /32.
