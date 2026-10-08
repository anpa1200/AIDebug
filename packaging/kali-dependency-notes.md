# Kali/Debian Dependency Notes

Dependency matrix verified 8 October 2026 against `pyproject.toml` and the
mirrored requirements files. Published 3.0.0 declares the same runtime/optional
floors as current source 3.1.0. The included `debian/` files remain a packaging
proposal; current Kali dependency resolution and build validation are pending.

## Current upstream floors

| Capability | Python requirement |
|---|---|
| Base | Python >=3.10; asn1crypto >=1.5.1; capstone >=5; cryptography >=43; pefile >=2023.2.7; pyelftools >=0.31; python-dotenv >=1.0.1; rich >=15.0.0; textual >=8.2.8 |
| Optional AI (`[ai]`) | anthropic >=0.120.2; openai >=2.0.0; yara-python >=4.5.4 |
| Optional dynamic (`[dynamic]`) | frida >=17.17.0,<18 |
| Build backend | setuptools >=83.0.0; wheel |

The OpenAI client serves OpenAI, Gemini's compatible endpoint and Ollama paths.
Provider clients do not establish live model availability. AI-generated YARA
candidates require the local compiler binding and bounded probe checks;
offline deterministic seeds do not use that validation path.

Bubblewrap and an ELF-capable C compiler are needed for `--source`; Ghidra and
compatible Java for reconstruction; GDB for local ELF debug. Learning requires
an x86-64 ELF compiler and Ghidra, but its compiler does not use the `--source`
Bubblewrap boundary. Frida targets need matching components and permissions.

## Historical Ubuntu Noble snapshot: 18 July 2026

This is preserved package-name/version evidence, not a current Kali check.
Compared with the current floors:

| Observed package | Historical version | Current floor comparison |
|---|---:|---|
| python3-capstone | 4.0.2 | Below 5 |
| python3-pefile | 2023.2.7 | Meets declared floor |
| python3-pyelftools | 0.30 | Below 0.31 |
| python3-packaging | 24.0 | Meets build/test helper floor |
| python3-rich | 13.7.1 | Below 15.0.0 |
| python3-textual | 0.1.13 | Below 8.2.8 |

The earlier snapshot also located `pybuild-plugin-pyproject`, `dh-python` and
`debhelper-compat`. It did not establish compatible versions for every current
runtime or optional requirement. Anthropic and Frida lacked matching packages
in that review environment; that is not a current package-availability claim.

## Packaging work still required

`debian/control` is not yet a complete mirror: it retains Rich >=13, lacks
explicit asn1crypto/cryptography/python-dotenv build/runtime dependencies, and
does not express the setuptools >=83 build floor. Generated `${python3:Depends}`
alone does not establish a usable build environment or target-package mapping.
Resolve names/versions in an actual Kali builder, align the control file and
run the build plus autopkgtest before claiming package readiness.

The proposed binary package keeps AI/Frida optional and exercises offline
behavior. Maintainers need separate dependency decisions for Anthropic,
OpenAI-compatible clients, yara-python and Frida. Upstream's optional extras
permit an offline base package; they do not make incomplete base dependencies
acceptable. No Debian control/runtime redesign is part of this documentation
update. See the [Kali request update draft](../docs/kali-new-tool-request.md).
