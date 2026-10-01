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

`microsoft_win32_catalog.json` is AIDebug's deterministic offline Windows API
catalog. It was generated from Microsoft's signed
`Microsoft.Windows.SDK.Win32Metadata` 71.0.14-preview package and
`Microsoft.Windows.SDK.Win32Docs` 0.1.42-alpha package. The snapshot contains
18,276 API names, 368 module names, function-to-module mappings, Microsoft Learn
links where supplied, and concise capability descriptions derived from Microsoft
Win32 namespaces. Catalog membership explains a general capability only; it does
not prove that the sample calls an API or that a string is reachable.
