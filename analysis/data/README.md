# Packaged analysis data

`iana_tlds.json` is an offline snapshot of IANA's authoritative
[`tlds-alpha-by-domain.txt`](https://data.iana.org/TLD/tlds-alpha-by-domain.txt).
The JSON records the source and snapshot version. IANA describes its registries
as published registry data, and its
[`Root Files`](https://www.iana.org/domains/root/files) page identifies this list
as data intended for software that needs to recognize valid top-level domains.
The snapshot is used only for deterministic TLD membership and does not imply
that a domain is registered, reachable, safe, or malicious.

`string_descriptions.json` contains AIDebug's neutral DLL/API descriptions.
