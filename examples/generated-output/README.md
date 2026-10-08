# Generated benign String Intelligence evidence

Generated 8 October 2026 with AIDebug 3.1.0, using the unchanged runtime from
`80b0b7172b592814504c405a16bf4cc0ce4161eb` plus this branch's documentation
updates. Python 3.13.12; capstone 5.0.7, pefile 2024.8.26, pyelftools 0.32, rich 15.0.0, textual 8.2.8. Existing local runtime
dependencies were used; this is not a claim of a fresh source installation.

[`true-strings.json`](true-strings.json) is the unmodified canonical exporter
output from the benign system `/bin/true` ELF. No binary is included, no target
was executed, no session database was created, and no provider was called.
Unlike the neighboring mock outputs, this is generated local evidence.

```bash
aidebug --binary /bin/true --offline --strings --no-tui \
  --string-encoding ascii --min-string-length 50 \
  --strings-output /tmp/true-strings.json
```

The run retained 8 ASCII records, scanned 26,936 bytes, and reported no
retention or value truncation. The minimum length deliberately limits this
example's inventory; it is not the default four-encoding/minimum-length run.
`ai_analysis` is null. The input SHA-256 is
`8a63c98320173f79e263115e10cefc170155e47d1fd4b5a70e4429d2699cae28`.
Output SHA-256: `682b1009b524b7f1b3377ce17b6f97b3db68aaf479e6c6e03f88120e5cbd451f`.

`/bin/true` varies across distributions. Reproduction should record the local
input hash, source revision, versions, options and coverage, rather than expect
these exact strings. This fixture demonstrates extraction/export contracts,
not malware detection or IOC accuracy.
