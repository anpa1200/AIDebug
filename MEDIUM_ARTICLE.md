# I Built an AI-Assisted Malware Debugger That Prioritizes Discovered Functions

## How I combined optional Claude analysis, Frida, Capstone, and deterministic heuristics into a review-first triage workflow

> Repository edition, corrected 2026-07-18: this text distinguishes current
> implementation behavior from illustrative sample output. The previously
> published Medium edition may not contain these corrections.

---

Malware reverse engineering is one of the most skill-intensive jobs in security. You sit with IDA Pro or Ghidra, stare at hundreds of unnamed functions full of obfuscated assembly, and try to build a mental model of what a threat actor's code is actually doing. It takes years to get fast at it.

I wanted to reduce that first-pass workload. So I built **AIDebug** — an open-source triage tool that discovers a bounded set of function candidates, applies deterministic pattern and library-identification heuristics, and can optionally ask Claude for explanations, risk hypotheses, and MITRE ATT&CK candidates. The analyst still decides what is correct.

This article walks you through what the tool does, how it works architecturally, and how to run it yourself on a real malware sample.

---

## Table of Contents

1. [The Problem With Traditional Malware Analysis](#the-problem-with-traditional-malware-analysis)
2. [What AIDebug Does](#what-aidebug-does)
3. [Architecture Deep Dive](#architecture-deep-dive)
   - [Layer 1: Static Analysis](#layer-1-static-analysis)
   - [Layer 2: Disassembler + Enrichment Pipeline](#layer-2-disassembler--enrichment-pipeline)
   - [Layer 3: Heuristic Library Identification](#layer-3-heuristic-library-identification)
   - [Layer 4: Malware Pattern Detection](#layer-4-malware-pattern-detection)
   - [Layer 5: Control Flow Graph](#layer-5-control-flow-graph)
   - [Layer 6: AI Analysis](#layer-6-ai-analysis)
   - [Layer 7: Dynamic Instrumentation (Frida)](#layer-7-dynamic-instrumentation-frida)
   - [Layer 8: Persistence (SQLite)](#layer-8-persistence-sqlite)
4. [Running It On a Real Sample](#running-it-on-a-real-sample)
5. [Installation](#installation)
6. [The TUI: Three Analysis Tabs](#the-tui-three-analysis-tabs)
7. [Ask the AI Follow-Up Questions](#ask-the-ai-follow-up-questions)
8. [Dynamic Mode: What Happens at Runtime](#dynamic-mode-what-happens-at-runtime)
9. [Reporting and Export](#reporting-and-export)
10. [Architecture Summary](#architecture-summary)
11. [Why Is Remote AI Optional?](#why-is-remote-ai-optional)
12. [Conclusion](#conclusion)

---

## The Problem With Traditional Malware Analysis

When you open a stripped Windows PE in a disassembler, you're greeted with hundreds of functions named `sub_401234`. Your job is to:

1. Read the assembly
2. Understand what each function does
3. Name it
4. Repeat — for hours

The bottleneck is not intelligence, it's throughput. An experienced analyst can only read assembly so fast. And when malware is packed, obfuscated, or uses indirect calls, even experienced analysts slow down dramatically.

There are also a dozen sub-tasks that eat time before you even get to the interesting code: separating compiler-generated CRT functions from hand-written malware code, identifying which functions are trivial wrappers, spotting XOR decryption loops before you waste 20 minutes trying to reverse them as normal code.

AI does not replace the analyst. AIDebug's deterministic layers classify pattern
candidates and construct control flow; the optional model can add an
interpretation while the analyst decides what the evidence actually supports.

---

## What AIDebug Does

AIDebug is a Python tool that runs a bounded pipeline on supported PE and ELF inputs:

1. **Static analysis** — PE/ELF parsing, section entropy and strings, PE import/export tables, and bounded ELF dynamic/function symbols
2. **Recursive-descent function discovery** — from entry point, following CALL targets
3. **Heuristic library identification** — exact import thunks can be excluded; collision-prone signature hints remain reviewable
4. **Malware pattern scanning** — 8 behavioral patterns detected before AI runs
5. **CFG construction** — basic block decomposition per function
6. **Claude AI analysis** — disassembly + patterns + context sent to Claude for structured explanation
7. **Frida dynamic instrumentation** — optional function/API hooks, register and stack snapshots, protection-transition hints, and bounded network-event capture

The UI is a Textual TUI with three main panels. The right panel has three tabs:

```
┌──────────────────┬────────────────────────────────┬────────────────────────────┐
│ FUNCTIONS (25)   │ DISASSEMBLY                    │ [AI Analysis][CFG]         │
│──────────────────│────────────────────────────────│ [Patterns]                 │
│ [CRIT] 0x40bcb8  │ 0x0040bcb8: push ebp           │────────────────────────────│
│ [HIGH] 0x4079b6  │ 0x0040bcb9: mov  ebp,esp       │ ▶ allocate_shellcode_mem   │
│ [MED ] 0x4015c2  │ 0x0040bcbb: sub  esp,0x20      │                            │
│ [LIB ] 0x40541c  │ 0x0040bcbe: push esi           │ SUMMARY:                   │
│ [LOW ] 0x401000  │ 0x0040bcbf: mov  eax,[ebp+8]   │ Calls NtAllocateVirtual-   │
│ [ -- ] 0x401a03  │ 0x0040bcc2: call 0x40efe6      │ Memory to allocate RWX     │
│                  │ ...                            │ memory. NT API used to     │
│                  │                                │ bypass EDR hooks on        │
│                  │ REGISTERS / SNAPSHOT           │ VirtualAlloc.              │
│                  │ (static mode)                  │                            │
│                  │                                │ RISK: CRITICAL             │
│                  │                                │ MITRE: T1055.001           │
└──────────────────┴────────────────────────────────┴────────────────────────────┘
  Ask AI: Why does it use Nt* instead of VirtualAlloc?
```

This UI sketch is illustrative. Its names, risk, ATT&CK mapping, and EDR-bypass
language are hypothetical model output, not findings established by the shown
instructions.

---

## Architecture Deep Dive

### Layer 1: Static Analysis

The `StaticAnalyzer` class handles PE and ELF files:

```python
from analysis import StaticAnalyzer

info = StaticAnalyzer().analyze('malware1.exe')

print(info.arch)         # 'x86'
print(info.entry_point)  # 0x401780
print(info.imports)      # [ImportInfo(dll='KERNEL32.dll', functions=[...])]
```

For PE files it uses `pefile` to extract architecture, image base, section names
and entropy, bounded import/export records, and both ASCII and UTF-16LE strings
with virtual-address mapping. Entropy above 7.0 is shown only as a possible
packing/encryption lead.

For ELF files it uses `pyelftools` to read bounded undefined dynamic symbols and
available function-symbol candidates, and supports Capstone selection paths
including RISC-V. It does not resolve each undefined symbol to a specific shared
object. Stripped binaries and architecture-specific edge cases can reduce
coverage.

### Layer 2: Disassembler + Enrichment Pipeline

The `Disassembler` uses Capstone for bounded recursive-descent function
discovery. After collecting the reachable candidates found within those limits,
it runs an enrichment pass:

```python
def _run_enrichment(self, addresses):
    detector = PatternDetector()
    flirt    = FlirtMatcher(self.info)

    for addr in addresses:
        func = self.functions[addr]
        func.patterns    = detector.detect(func)   # pre-AI pattern scan
        match = flirt.identify(func)
        if match:
            func.flirt_match = match
            func.is_library  = match.skip_ai
```

Each discovered function gets pattern detection and library-identification hints before a remote AI call is made. Discovery is bounded recursive descent from entry/export candidates, so indirect, unreachable, packed, or overlaid code can be missed.

### Layer 3: Heuristic Library Identification

One of the biggest noise sources in PE analysis is compiler-inserted CRT code. Functions like `_memset`, `_strlen`, `_malloc`, and the whole C runtime startup chain appear in virtually every MSVC-compiled binary. Sending them all to Claude wastes tokens and clutters results.

AIDebug uses a lightweight, FLIRT-inspired heuristic system. It is not an authoritative FLIRT database:

**Strategy 1 — Import wrapper detection:** A function that's just `jmp [IAT_entry]` is named after the imported API it wraps. This covers the vast majority of API call stubs in PE files.

**Strategy 2 — CRC16 prologue match:** The first 32 instruction bytes are hashed (with immediate values normalized where possible) and looked up in `analysis/data/flirt_sigs.json`.

**Strategy 3 — Single-import call inference:** A small function that calls one known import receives an inferred wrapper hint, but is not suppressed from review.

**Strategy 4 — Trivial stub detection:** Very small functions receive an inferred stub hint, but are not assumed benign.

Result: the function list can prioritize likely wrapper noise. Only a verified import thunk is treated as exact enough to skip remote analysis; the 16-bit checksum can collide and needs manual verification:

```
[LIB ] 0x40541c   imported_api     (2 insns)    ← verified IAT thunk; remote call skipped
[HINT] 0x405674   possible_strlen  (8 insns)    ← heuristic; still reviewed
[CRIT] 0x40bcb8   allocate_rwx_region (31 insns) ← selected for analysis
[HIGH] 0x4079b6   check_os_registry   (40 insns) ← selected for analysis
```

### Layer 4: Malware Pattern Detection

`PatternDetector` scans each discovered function's bounded instruction list for 8 behavioral patterns before optional AI analysis runs. Detected patterns are:

- **`xor_decryption_loop`** (HIGH): backward jump plus a non-zeroing XOR in the loop — a broad obfuscation/decryption heuristic that needs operand review
- **`stack_string`** (MEDIUM): 4+ consecutive `mov byte ptr [esp+N]` — anti-string-scan technique
- **`api_hash_resolution`** (HIGH): ROR/ROL + XOR loop — shellcode loader technique for resolving API names by hash
- **`rdtsc_timing_check`** (MEDIUM/HIGH): RDTSC instruction — sandbox/VM timing evasion
- **`direct_syscall`** (contextual): Windows candidates are HIGH, Linux syscalls are INFO, and unknown-OS cases are MEDIUM
- **`nop_sled`** (INFO): 5+ consecutive NOPs — shellcode alignment
- **`null_preserving_xor`** (HIGH): test/jz/xor sequence — common in XOR-encoded shellcode to avoid null bytes
- **`base64_alphabet_reference`** (MEDIUM): reference to a known Base64 alphabet string

These patterns are injected into the AI prompt, so Claude gets pre-flagged behavioral context rather than having to infer everything from raw assembly. The patterns also appear independently in the Patterns tab — no AI call required to see them.

### Layer 5: Control Flow Graph

`CFGBuilder.build(func)` splits the function into basic blocks at branch/jump/ret boundaries and links blocks via successor/predecessor edges. The result is a `CFG` object with a dict of `BasicBlock` entries.

Two renderers:

- **`CFGTextRenderer`** — renders to multi-line ASCII art with box-drawing characters for the TUI
- **`CFGSVGRenderer`** — renders to a self-contained inline SVG for HTML reports, using a BFS layout algorithm

An illustrative captured function from `malware1.exe` (`0x4015c2`, 26 instructions, `stack_string` pattern):

```
CFG: 6 basic blocks

┌── ◆ Block 0x004015c2 (12 insns) ──
│  0x004015c2: push     ebp
│  0x004015c3: mov      ebp, esp
│  0x004015c5: sub      esp, 0x4c
│  … (9 more)
└── → 0x004015e9, 0x004015e1

┌── ◆ Block 0x004015e1 (2 insns) ──
│  0x004015e1: xor      eax, eax
│  0x004015e3: ret
└── [RET]
```

The CFG shows immediately what the branching structure looks like without reading every instruction.

### Layer 6: AI Analysis

For each selected function other than a verified import thunk, the optional remote path builds a bounded structured prompt with binary metadata, imports, disassembly, referenced strings, cross-references, and pre-detected patterns:

```
BINARY INFO:
  File      : malware1.exe
  Arch      : x86 32-bit
  OS Target : Windows

KNOWN IMPORTED APIs:
  KERNEL32.dll: WaitForSingleObject, LoadLibraryA, ...
  ADVAPI32.dll: CryptImportKey, CryptDecrypt, ...

FUNCTION ADDRESS: 0x40bcb8

DISASSEMBLY (31 instructions):
0x0040bcb8:  push     ebp
...
0x0040bce4:  call     NtAllocateVirtualMemory

REFERENCED STRINGS:
  "NtAllocateVirtualMemory"

PRE-DETECTED PATTERNS:
  [HIGH] xor_decryption_loop: xor byte ptr [eax], cl at 0x40bcd1
```

The following is illustrative structured model output, not verified ground truth:

```json
{
  "suggested_name": "allocate_rwx_region",
  "summary": "References NtAllocateVirtualMemory. Trace the arguments and callers to determine the target process and requested protection; the API name alone does not prove injection or EDR bypass.",
  "parameters": [
    {"name": "size", "type": "ULONG_PTR", "description": "Size of region"},
    {"name": "protect", "type": "ULONG", "description": "0x40 = PAGE_EXECUTE_READWRITE"}
  ],
  "return_value": "Pointer to allocated RWX region, or NULL",
  "behaviors": [
    "NT native memory-management API reference",
    "Possible executable-memory allocation if the protection argument is confirmed as 0x40"
  ],
  "mitre_technique": null,
  "risk_level": "MEDIUM",
  "notes": "Confirm the complete call sequence before assigning an ATT&CK technique."
}
```

That kind of note can suggest a next manual check, but it can also be wrong and
must be confirmed against callers and runtime evidence.

### Layer 7: Dynamic Instrumentation (Frida)

The dynamic engine provides three Frida script families. Hook availability and
coverage depend on the target OS, architecture, modules, Frida version, ASLR/PIE
mapping, and whether the analyst attaches before the relevant activity:

**`tracer.js`** — hooks a configured set of Win32 APIs and records bounded call arguments when those exports exist.

**`unpack_detector.js`** — observes selected allocation/protection APIs. A suspicious writable-to-executable transition can trigger a scan for an x86 prologue-shaped byte sequence. This is an analyst lead, not proof that unpacking completed or that the candidate is the original entry point:

```javascript
// Scan for PE-like prologue in newly-executable region
var boundedSize = Math.min(size, 256);
for (var i = 0; i < boundedSize - 2; i++) {
    var b0 = mem[i], b1 = mem[i+1], b2 = mem[i+2];
    if (b0 === 0x55 && b1 === 0x8B && b2 === 0xEC) {
        oepHint = ptr(baseAddr).add(i).toString();
        break;
    }
}
```

**`network_tracer.js`** — hooks Winsock (`connect`, `send`, `recv`, `sendto`, `recvfrom`) and WinInet (`InternetOpenUrl`, `HttpSendRequest`, `InternetReadFile`). Captures actual buffer bytes up to 512 bytes as hex strings, and parses `sockaddr` structs to extract IP and port:

```javascript
// Parse sockaddr for IP:port
var family = sockaddr.readU16();
if (family === 2) {  // AF_INET
    var port = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8());
    var ip = [0,1,2,3].map(function(i) {
        return sockaddr.add(4+i).readU8();
    }).join('.');
    send({type:'network', event:'connect', ip:ip, port:port, ...});
}
```

The result is bounded API-level network telemetry that may help an analyst
correlate destinations and buffers. It is not packet capture, complete C2
reconstruction, TLS decryption, or a replacement for a network sensor.
Connect and send events are emitted after the API reports success; send sizes
use the API's returned byte count. A bounded socket-to-peer map associates later
`send` and `recv` events with a successfully connected IPv4 destination when
that context is available. This correlation can still be absent or incomplete.

The engine records function entry/exit registers and a bounded entry stack when
hooks fire. It also correlates bounded 64-byte before/after pointer-region
captures by invocation ID. Unreadable pointers, missed hooks, recursion limits,
and target-specific Frida behavior can still leave a diff incomplete. Dynamic
instrumentation uses the lower of `--max-functions` and a 50-function hook
ceiling. Each script must report readiness; the CLI shows its current installed
hook count and marks the run degraded when instrumentation errors are reported.
A ready observer with zero hooks can be waiting for a watched module and is not
evidence that behavior was captured.

### Layer 8: Persistence (SQLite)

Six primary tables in the configured SQLite session database:
- `sessions` — binary metadata per analysis run
- `function_traces` — disassembly + AI analysis JSON per function
- `api_calls` — Win32 API call log from dynamic mode
- `detected_patterns` — malware pattern results per function
- `network_events` — network events from dynamic mode
- `runtime_events` — protection-transition and related runtime hints

The database supports later report generation and session review. A completed
result can be reused across sessions only when the sample SHA-256, function
address, and analyzer cache key match; model/prompt or offline-cache changes
invalidate the match.

---

## Running It On a Real Sample

The following is a historical, illustrative walkthrough from `malware1.exe`.
The sample is intentionally not in the repository, and CI cannot reproduce
these exact values. Treat every quoted model conclusion as a hypothesis, not
validated ground truth.

### Step 1: Static fingerprint

```
[*] Format   : PE x86 32-bit  (Windows)
[*] EntryPoint: 0x401780
[*] Sections  : ['.text', '.rdata', '.data', '.reloc', 'dhqj']
[*] Imports   : 89 functions from 8 DLLs
[!] Possible packing: [dhqj] (entropy > 7.0)
```

Immediate red flags:
- **Section `dhqj`** — non-standard section name, custom packer
- **Entropy > 7.0** — packed or encrypted content
- **Imports**: `Secur32.dll` (SSP manipulation), `ADVAPI32.dll` with `CryptDecrypt`/`CryptImportKey`, `ntdll.dll` NT-native calls

### Step 2: Function discovery + enrichment

In this capture, 25 candidates were found and several library/pattern hints were
shown. Current code skips remote analysis only for verified import thunks;
checksum and structural matches remain collision-prone hints:

```
  [FLIRT] sub_00405412  → _memset (msvcrt) — skipped
  [FLIRT] sub_00405674  → _strlen (msvcrt) — skipped
  [PAT  ] 0x004015c2    → stack_string (MEDIUM)
  [PAT  ] 0x00401000    → xor_decryption_loop (HIGH)
```

I already know where to look before Claude runs a single analysis.

### Step 3: Historical AI hypotheses to validate

**`0x40bcb8` — possible native memory-management wrapper**
> The visible API reference suggests memory allocation. Confirm the argument
> order, protection value, target process, and callers before claiming RWX
> allocation, injection, or defense evasion.

**`0x4079b6` — possible OS/registry query**
> Registry access can support many benign or malicious workflows. Opening a key
> and seeing a GUID-like string does not establish persistence without the
> target path, write operation, and surrounding control flow.

**`0x4015c2` — stack-string candidate**
> Consecutive byte writes support a stack-string hypothesis. Recover the final
> bytes and their use before deciding whether this is obfuscation or mapping it
> to ATT&CK.

**`0x401000` — XOR-loop candidate**
> A backward branch around non-zeroing XOR is a broad heuristic. Inspect the
> operands, buffer, loop bounds, and output use before calling it configuration
> or C2 decoding.

This produces a prioritized hypothesis: possible executable-memory allocation,
registry behavior, stack-string construction, and XOR-obfuscated data. Each item
still needs confirmation in a disassembler, sandbox, or debugger.

---

## Installation

The public v1.1.0 package is on PyPI, but the corrected offline/dependency and
safety workflow in this repository is newer than that release. Until a new
version is tagged, install the current code from a source checkout:

```bash
git clone https://github.com/anpa1200/AIDebug.git
cd AIDebug
pip install -e .
aidebug --help
```

PyPI package: **https://pypi.org/project/1200km-aidebug/**

Current public release: **https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0**

Deterministic offline analysis needs only the base package:

```bash
aidebug --binary /path/to/sample --offline --no-tui
```

Install authorized remote AI or dynamic instrumentation separately:

```bash
pip install -e ".[ai]"       # remote AI + local validation of AI YARA candidates
pip install -e ".[dynamic]"  # Frida 17.x
pip install -e ".[all]"      # both
```

If you prefer running from source:

```bash
git clone https://github.com/anpa1200/AIDebug
cd AIDebug
pip install -e ".[all]"
export ANTHROPIC_API_KEY=sk-ant-...
```

### Run in TUI mode

```bash
aidebug --binary /path/to/sample.exe --offline
```

### Run in CLI mode (headless, good for scripting)

```bash
aidebug --binary sample.exe --offline --no-tui
```

### Generate HTML report in one shot

```bash
aidebug --binary sample.exe --offline --no-tui --report
```

### Dynamic mode (requires Frida)

```bash
# Start the sample separately inside the authorized isolated target, then attach.
# AIDebug does not launch or configure Wine/sandbox isolation for you.
aidebug --binary sample.exe --mode dynamic --pid 4521 --offline
```

Running bulk CLI, report-backed, or dynamic analysis with remote AI requires
the `ai` extra, `ANTHROPIC_API_KEY`, and `--accept-ai-cost`. This is both a cost
acknowledgement and a reminder that sample-derived evidence is sent off host.

---

## The TUI: Three Analysis Tabs

The right panel has three tabs that combine available evidence for a discovered function without claiming complete coverage.

**AI Analysis tab** — the selected analyzer's structured output. With the `ai`
extra and remote mode, this can include Claude-generated names, summaries,
parameters, behaviors, risk, and ATT&CK candidates. Offline mode instead shows
deterministic evidence and does not invent ATT&CK conclusions.

**CFG tab** — The function's control flow graph as ASCII art. You see immediately whether you're looking at a simple linear function or a complex loop-with-branches before reading a single instruction.

```
CFG: 6 basic blocks

┌── ◆ Block 0x004015c2 (12 insns) ──
│  0x004015c2: push     ebp
│  …
└── → 0x004015e9, 0x004015e1

┌── ◆ Block 0x004015e9 (6 insns) ──   ← loop body
│  0x004015e9: mov      al, [ebp-0x3c+ecx]
│  0x004015ef: xor      al, 0x41
│  …
└── → 0x004015e9, 0x004015fb           ← loops back
```

**Patterns tab** — Pre-detected behavioral patterns. Available immediately, no AI needed:

```
[HIGH] xor_decryption_loop  @ 0x004015ed
  XOR loop on memory with backward branch
  Evidence: xor byte ptr [esi+ecx], al; jne 0x4015e9

[MED ] stack_string  @ 0x004015c2
  4+ consecutive byte-by-byte stack writes
  Evidence: mov byte ptr [ebp-0x3c], 0x68
```

Dynamic network events are logged by the CLI and can be persisted into the
session/JSON export. The current TUI does not expose a Network tab.

---

## Ask the AI Follow-Up Questions

With a function selected, type questions at the bottom bar:

- *"What protection constant should I look for to confirm it's RWX?"*
- *"Why use NtAllocateVirtualMemory instead of VirtualAlloc?"*
- *"What should I look at next to confirm process injection?"*
- *"Write a YARA rule for this function's behavior"*
- *"Is the XOR key hardcoded or derived at runtime?"*

Remote follow-up uses the selected function's bounded prompt context and a
limited conversation history. It remains model output, not a senior analyst's
decision. Offline mode deliberately disables follow-up inference.

---

## Dynamic Mode: What Happens at Runtime

When you run with `--mode dynamic`, three things happen in parallel as the process executes:

**1. Per-function runtime context.** A successfully installed hook can record
entry/exit registers and a bounded entry stack. Static addresses may not be
valid runtime addresses under ASLR/PIE or rebasing, so hook coverage must be
verified. Remote mode may send captured runtime context to the provider.

**2. Protection-transition hints.** The detector watches selected protection
calls. A suspicious writable/executable transition can produce a possible
unpacking lead:

```
[Unpack] Writable allocation tracked @ 0x00870000 size=65536
[Unpack] Executable protection transition observed (heuristic)
[Unpack] Region : 0x00870000
[Unpack] Entry candidate: 0x00870010  new_protect=0x20
```

This gives the analyst a byte-pattern hint to investigate. The tool does not
automatically dump, rebase, re-disassemble, or re-analyze that region.

**3. Network API telemetry.** When supported hooks fire, selected calls and
bounded buffer bytes are recorded. Missed calls, encrypted traffic, alternate
stacks, early activity, and unsupported exports remain possible:

```
connect  connect   192.168.1.105:4444   0 bytes
send     send      192.168.1.105:4444   128 bytes    ← beacon
recv     recv      192.168.1.105:4444   64 bytes     ← response
```

Events delivered to the host callbacks can be saved to the local database for
review. The database is unencrypted and needs case-specific access and retention controls.

---

## Reporting and Export

After analysis, generate reports directly:

```bash
# HTML report (self-contained, dark theme, CFG SVGs embedded)
aidebug --binary sample.exe --offline --no-tui --report

# YARA candidates for HIGH/CRITICAL functions
aidebug --binary sample.exe --offline --no-tui --yara

# Versioned JSON for a custom downstream adapter
aidebug --binary sample.exe --offline --no-tui --json-export

# All three, custom output directory
aidebug --binary sample.exe --offline --no-tui --report --yara --json-export --out-dir ./reports/
```

The HTML report includes an interactive sidebar with the functions analyzed in
that bounded session sorted by risk. Each function detail view shows:

- the available deterministic or remote-AI summary, risk, behaviors, and
  optional ATT&CK candidate
- **Detected patterns section** with severity-coded entries
- available function evidence and stored pattern findings
- Color-coded disassembly

---

## Architecture Summary

```
malware.exe
     │
     ▼
┌────────────────────────────────────────────────────────────┐
│  StaticAnalyzer (pefile / pyelftools)                      │
│  → BinaryInfo: arch, sections, imports, strings, entropy   │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  Disassembler (Capstone)                                   │
│  → Function objects: instructions, calls_to, strings_ref   │
│                                                            │
│  Enrichment pipeline (bounded discovered functions):       │
│  ├── FlirtMatcher  → exact thunk or heuristic hints         │
│  └── PatternDetector → patterns []                         │
└────────────────────┬───────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │ (static)            │ (dynamic, optional)
          ▼                     ▼
          │             ┌─────────────────────────────┐
          │             │  DebugEngine (Frida)         │
          │             │  tracer.js      → API calls  │
          │             │  unpack_detector.js → transition hint│
          │             │  network_tracer.js  → bounded events │
          │             │  hook_function  → snapshots  │
          │             └─────────────┬───────────────┘
          │                           │
          ▼                           ▼
┌────────────────────────────────────────────────────────────┐
│  CFGBuilder  →  CFG (BasicBlock dict)                      │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  AIAnalyzer (Claude claude-opus-4-8, configurable)         │
│  Input: disassembly + imports + strings + patterns         │
│       + xrefs + snapshot (if dynamic)                      │
│  Output: name, summary, risk, MITRE, params, notes         │
│  Verified import thunks → remote analysis skipped          │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  TraceStore (SQLite)                                       │
│  sessions │ function_traces │ api_calls                    │
│  network_events │ runtime_events │ detected_patterns        │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  Textual TUI                                               │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ Function │  │ Disassembly  │  │ [AI Analysis][CFG  ] │ │
│  │   List   │  │   + Regs     │  │ [Patterns]           │ │
│  └──────────┘  └──────────────┘  └──────────────────────┘ │
│                                     + Chat bar             │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  Reporting                                                 │
│  html_report.py   → .html (CFG SVG + patterns embedded)    │
│  yara_generator.py → .yar (reviewable candidate rules)     │
│  json_export.py   → .json (AIDebug session schema v2)      │
└────────────────────────────────────────────────────────────┘
```

---

## Why Is Remote AI Optional?

The remote path uses Anthropic's structured message API because it supports the
JSON-oriented prompt and bounded follow-up workflow used by the project. This
repository does not contain a controlled multi-model benchmark, so it does not
claim that one provider is uniquely accurate or that generated ATT&CK mappings
are correct. The model is configurable and can change independently of the
public package version.

Remote processing also has a material data boundary: filename and hash context,
imports, disassembly, referenced strings, cross-references, pattern hints, and
optional runtime context may leave the lab. Install the `ai` extra and use this
mode only after reviewing provider policy, authorization, retention, and cost.
The base package's `--offline` mode keeps analysis local and makes its inference
limits explicit.

---

## Conclusion

AIDebug is not a replacement for IDA Pro or a seasoned reverse engineer. Its
bounded discovery, heuristic library hints, pattern candidates, CFG view, and
optional model explanations can help prioritize where to look next. None of
those layers establishes benignness, attribution, or a production detection by
itself.

The intended outcome is a faster, structured first pass whose findings can be
verified with full reverse-engineering and sandbox tools.

The full source is at **https://github.com/anpa1200/AIDebug**.

Install the corrected current source checkout as shown above:

```bash
pip install -e .
# or: pip install -e ".[ai]" for authorized remote analysis
```

The PyPI command `pip install 1200km-aidebug` currently installs historical
v1.1.0, not the post-v1.1.0 source behavior described in this repository
edition.

Release page: **https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0**

If you're working in threat intelligence, incident response, or malware research — try it on your next sample and let me know what you find.

---

*All analysis in this article was performed in an isolated VM environment on samples used for security research. Always analyze malware in a properly isolated sandbox.*

---

**Tags:** `malware-analysis` `reverse-engineering` `python` `security` `ai` `llm` `frida` `claude` `capstone` `yara`

---

**Published on Medium:** https://medium.com/@1200km/ai-powered-malware-debugger-that-explains-every-function-it-sees-2a28ef75df8a
