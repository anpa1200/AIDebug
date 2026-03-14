# AIDebug — AI-Assisted Malware Reverse Engineering Debugger

> Step-by-step malware debugger powered by Claude AI. Analyzes every function's inputs, outputs, and behavior — and explains it in plain English.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Static Analysis Mode (TUI)](#static-analysis-mode-tui)
  - [Static Analysis Mode (CLI / headless)](#static-analysis-mode-cli--headless)
  - [Dynamic Analysis Mode (Frida)](#dynamic-analysis-mode-frida)
  - [Reporting & Export](#reporting--export)
  - [Session Management](#session-management)
- [TUI Interface Guide](#tui-interface-guide)
  - [Layout](#layout)
  - [Keyboard Shortcuts](#keyboard-shortcuts)
  - [Function List Panel](#function-list-panel)
  - [Disassembly Panel](#disassembly-panel)
  - [Right Panel Tabs](#right-panel-tabs)
  - [Chat Bar](#chat-bar)
- [AI Analysis Output](#ai-analysis-output)
  - [Risk Levels](#risk-levels)
  - [MITRE ATT&CK Mapping](#mitre-attck-mapping)
  - [Follow-up Questions](#follow-up-questions)
- [FLIRT Signature Matching](#flirt-signature-matching)
- [Malware Pattern Detection](#malware-pattern-detection)
- [Control Flow Graph](#control-flow-graph)
- [Dynamic Mode Features](#dynamic-mode-features)
  - [Memory Diff](#memory-diff)
  - [Unpacking Detection](#unpacking-detection)
  - [Network Traffic Capture](#network-traffic-capture)
- [Supported Binary Formats](#supported-binary-formats)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Dynamic Mode Setup](#dynamic-mode-setup)
  - [Linux + Wine (Windows PE)](#linux--wine-windows-pe)
  - [Windows (native)](#windows-native)
  - [RISC-V / IoT ELF (QEMU)](#risc-v--iot-elf-qemu)
- [Database & Caching](#database--caching)
- [Sandbox Safety](#sandbox-safety)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

AIDebug is a Python-based malware analysis tool that combines:

- **Static analysis** — PE/ELF parsing, section entropy, import table, string extraction
- **Capstone disassembly** — recursive-descent function discovery across x86, x86-64, ARM, RISC-V
- **FLIRT signature matching** — automatically identifies library functions (msvcrt, zlib, OpenSSL) and skips AI analysis for them, saving tokens and reducing noise
- **Malware pattern detection** — pre-analysis scan for XOR decryption loops, stack strings, API hash resolution, RDTSC timing checks, direct syscalls, and more
- **CFG visualization** — control flow graph per function, rendered as text in the TUI and as inline SVG in HTML reports
- **Claude AI** — each function's disassembly, patterns, and context are sent to Claude, which returns a structured explanation: name, summary, parameters, return value, behaviors, risk level, MITRE ATT&CK technique
- **Frida dynamic instrumentation** — optional runtime mode that hooks function entry/exit, captures register and memory state, detects unpacking, and logs network traffic
- **Textual TUI** — three-panel terminal UI with a tabbed right panel (AI Analysis / CFG / Patterns / Network) and a built-in chat interface for follow-up questions
- **SQLite persistence** — all analyses, patterns, and network events are cached locally; re-running the same binary costs zero API calls

---

## Features

| Feature | Description |
|---|---|
| PE32 / PE64 / ELF analysis | Parses sections, imports, exports, strings, entropy |
| Recursive-descent disassembler | Follows CALL targets from entry point, builds call graph |
| **FLIRT signature matching** | Identifies library functions by CRC16 prologue; skips AI for them |
| **Malware pattern detection** | 8 patterns: XOR loop, stack strings, API hashing, RDTSC, direct syscall, NOP sled, null-safe XOR, Base64 table |
| **CFG visualization** | Basic block decomposition; text in TUI, inline SVG in HTML report |
| AI function explanation | Name suggestion, summary, parameters, return value, behaviors |
| Risk classification | LOW / MEDIUM / HIGH / CRITICAL per function |
| MITRE ATT&CK mapping | Technique ID and name per function |
| AI chat | Ask follow-up questions about any function in context |
| Frida hooks | Runtime register/stack snapshots at function entry and exit |
| **Memory diff** | Before/after heap state captured at function entry and exit |
| **Unpacking detection** | Hooks VirtualProtect/NtProtectVirtualMemory; fires on RWX→R-X transitions |
| **Network traffic capture** | Hooks Winsock + WinInet; captures actual buffer bytes with IP/port/URL |
| Win32 API tracer | Hooks 80+ APIs across kernel32, advapi32, ntdll, wininet, ws2_32, user32 |
| HTML report | Self-contained dark-themed report with CFG SVGs and pattern sections |
| YARA rule generation | AI-generated YARA rules for HIGH/CRITICAL functions |
| JSON export | Structured export for SIEM/SOAR integration (schema `aidebug/session/v1`) |
| Result caching | SQLite DB — analyses survive restarts, no repeat API calls |
| Batch analysis | Analyze all functions at once with a single keypress |
| Session history | Browse and search past analysis sessions |

---

## Requirements

| Dependency | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Runtime |
| anthropic | latest | Claude API client |
| capstone | latest | Disassembly engine |
| pefile | latest | PE32/PE64 parsing |
| pyelftools | latest | ELF parsing |
| frida | latest | Dynamic instrumentation (optional) |
| textual | 0.52+ | Terminal UI framework |
| rich | 13+ | Text formatting |

**API key required:** You need an Anthropic API key with access to `claude-opus-4-6`.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/anpa1200/AIDebug
cd AIDebug

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Set your Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...

# Optionally add to your shell profile to persist it:
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.bashrc
```

---

## Quick Start

```bash
# Analyze a Windows PE sample — opens the TUI
python main.py --binary /path/to/sample.exe

# Analyze and print results to terminal (no TUI)
python main.py --binary /path/to/sample.exe --no-tui

# Analyze and generate an HTML report in one shot
python main.py --binary sample.exe --no-tui --report

# Analyze a Linux ELF
python main.py --binary /path/to/sample.elf
```

---

## Usage

### Static Analysis Mode (TUI)

```bash
python main.py --binary <path>
```

This is the default mode. The tool will:

1. Parse the binary (PE or ELF)
2. Discover all reachable functions via recursive descent from the entry point
3. Run FLIRT matching and malware pattern detection on every function
4. Open the three-panel TUI
5. Wait for you to select a function — AI analysis runs on demand when you select one
6. Press `A` to batch-analyze all functions at once

### Static Analysis Mode (CLI / headless)

```bash
python main.py --binary <path> --no-tui
```

Useful for scripting or running on remote servers without a terminal. The tool iterates through all discovered functions, sends each to Claude, and prints the results to stdout. Library functions identified by FLIRT are skipped automatically.

Example output:

```
[*] Loading: malware1.exe
[*] Format   : PE x86 32-bit  (Windows)
[*] EntryPoint: 0x401780
[*] Sections  : ['.text', '.rdata', '.data', '.reloc', 'dhqj']
[*] Imports   : 89 functions from 8 DLLs
[*] Strings   : 312 found
[!] Possible packing: ['dhqj'] (entropy > 7.0)
[*] Discovering functions…
[*] Found 25 functions.
[*] Session ID: 3

  [FLIRT] sub_00405412  → _memset (msvcrt) — skipped AI
  [AI]    0x00401000  sub_00401000  (16 insns)… [LOW ] entry_point_init
  [AI]    0x0040bcb8  sub_0040bcb8  (31 insns)… [CRIT] allocate_rwx_region
           → Calls NtAllocateVirtualMemory directly to allocate RWX memory...
           → MITRE: T1055.001 - Process Injection: DLL Injection
  [AI]    0x004079b6  sub_004079b6  (40 insns)… [HIGH] check_os_open_registry
           → Queries Windows version and opens registry key via NtOpenKey...
           → MITRE: T1547.001 - Boot or Logon Autostart Execution
  ...

=== Risk Summary ===
  CRITICAL  : 1
  HIGH      : 3
  MEDIUM    : 4
  LOW       : 17

[*] Results saved to: /home/user/AIDebug/traces.db
```

### Dynamic Analysis Mode (Frida)

```bash
# Spawn a new process and attach
python main.py --binary <path> --mode dynamic

# Attach to an already-running process
python main.py --binary <path> --mode dynamic --pid <PID>
```

Dynamic mode requires Frida. The tool will:

1. Spawn the binary (or attach to existing PID)
2. Hook the first 50 discovered functions for entry/exit interception
3. Load the Win32 API tracer (80+ hooks)
4. Load the unpacking detector (VirtualProtect hooks)
5. Load the network traffic capture (Winsock + WinInet hooks)
6. Resume the process
7. As functions execute, capture register/memory snapshots, network events, and API calls — all streamed into the TUI Network tab and persisted to the database

### Reporting & Export

```bash
# Generate HTML report after analysis
python main.py --binary sample.exe --no-tui --report

# Generate YARA rules for HIGH/CRITICAL functions
python main.py --binary sample.exe --no-tui --yara

# Export session as JSON for SIEM/SOAR
python main.py --binary sample.exe --no-tui --json-export

# All three at once, custom output directory
python main.py --binary sample.exe --no-tui --report --yara --json-export --out-dir ./reports/

# Generate report from a previously saved session (no re-analysis)
python main.py --session 3 --report
```

The HTML report is self-contained (single `.html` file, no external dependencies). It includes:
- Binary metadata and risk summary bar
- Interactive sidebar with all functions sorted by risk
- Per-function: AI summary, MITRE tag, behaviors, parameters, detected patterns, inline CFG SVG, color-coded disassembly

### Session Management

```bash
# List all past analysis sessions
python main.py --list-sessions

# Use a custom database path
python main.py --binary sample.exe --db /path/to/custom.db
```

---

## TUI Interface Guide

### Layout

```
┌─ AIDebug ─ malware1.exe │ PE x86 │ 25 functions │ SHA256: 8d3634a7... ──────┐
├──────────────────────┬──────────────────────────────┬────────────────────────┤
│  FUNCTIONS           │  DISASSEMBLY                 │  [AI Analysis][CFG]    │
│ ─────────────────── │ ───────────────────────────  │  [Patterns ][Network]  │
│  [CRIT] 0x40bcb8    │  0x0040bcb8: push  ebp       │ ──────────────────────│
│  [HIGH] 0x4079b6    │  0x0040bcb9: mov   ebp,esp   │  [CRIT] alloc_rwx      │
│  [HIGH] 0x40f013    │  0x0040bcbb: sub   esp,0x20  │                        │
│  [MED ] 0x4015c2    │  0x0040bcbe: push  esi       │  Summary:              │
│  [LOW ] 0x401000    │  ...                         │  Allocates RWX mem     │
│  [LOW ] 0x4012e6    │                              │  via NT syscall...     │
│  [LIB ] 0x40541c    │  REGISTERS / SNAPSHOT        │                        │
│  [ -- ] 0x401a03    │  (static mode — no snapshot) │  Risk:   CRITICAL      │
│                      │                              │  MITRE:  T1055.001     │
│                      │                              │                        │
│                      │                              │  Behaviors:            │
│                      │                              │  • RWX allocation      │
│                      │                              │  • NT API evasion      │
├──────────────────────┴──────────────────────────────┴────────────────────────┤
│  Ask AI: _                                                                    │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate function list |
| `Enter` | Select function → show disassembly + trigger AI analysis |
| `A` | Batch analyze all functions (queues all to Claude in background) |
| `Ctrl+F` | Focus the chat input bar |
| `Escape` | Return focus to function list from chat |
| `Q` | Quit |

### Function List Panel

Shows all discovered functions sorted by risk level (CRITICAL first, unanalyzed last). Each row:

```
[CRIT]  0x40bcb8   allocate_rwx_region    31
^risk   ^address   ^AI-suggested name     ^instruction count
```

Risk badges before AI analysis show `[ -- ]`. Library functions identified by FLIRT show `[LIB ]` and display the matched library name instead of an AI-generated name. After analysis the badge updates in real time.

### Disassembly Panel

Shows the full disassembly of the selected function with color-coded mnemonics:

| Color | Mnemonic category |
|-------|-------------------|
| Yellow | `call` — function calls |
| Green | `ret` / `retn` — returns |
| Magenta | `jmp`, `je`, `jne`, etc. — jumps/branches |
| Cyan | `push` / `pop` — stack operations |
| White | `mov`, `lea` — data movement |

Referenced strings are shown below the disassembly.

In dynamic mode, the lower sub-panel shows the register state captured at function entry/exit, including memory diffs for pointer-valued registers.

### Right Panel Tabs

The right panel has four tabs:

**AI Analysis** — Claude's structured analysis for the selected function (name, summary, risk, MITRE, parameters, return value, behaviors, notes). The chat bar at the bottom sends follow-up questions into this context.

**CFG** — Control flow graph of the selected function rendered as ASCII art with basic blocks, successor/predecessor links, and instruction counts. Example:

```
CFG: 6 basic blocks

┌── ◆ Block 0x004015c2 (12 insns) ──
│  0x004015c2: push     ebp
│  0x004015c3: mov      ebp, esp
│  … (10 more)
└── → 0x004015e9, 0x004015e1

┌── ◆ Block 0x004015e1 (2 insns) ──
│  0x004015e1: xor      eax, eax
│  0x004015e3: ret
└── [RET]
```

**Patterns** — Pre-detected malware behavioral patterns in the function. Displayed immediately without an AI call, color-coded by severity (HIGH = red, MEDIUM = yellow, INFO = cyan). Each entry shows the pattern name, description, and evidence snippet.

**Network** — Live stream of network events captured in dynamic mode. Shows event type, API call, destination IP/URL, and byte count. Updated in real time as the target process makes network connections.

### Chat Bar

Type any question at the bottom bar. The AI has full context of the currently selected function and the entire analysis conversation. Examples:

```
Ask AI: Why use NtAllocateVirtualMemory instead of VirtualAlloc?
Ask AI: Write a YARA rule for this function's behavior
Ask AI: What is 0x40 as a memory protection constant?
Ask AI: What Win32 APIs would I see called after this in a process injection chain?
Ask AI: Is this a compiler artifact or hand-written code?
```

---

## AI Analysis Output

### Risk Levels

| Level | Badge | Meaning |
|-------|-------|---------|
| `CRITICAL` | `[CRIT]` | Directly malicious: process injection, persistence installation, credential theft, ransomware behavior |
| `HIGH` | `[HIGH]` | Strongly suspicious: registry modification, network connection setup, file system manipulation |
| `MEDIUM` | `[MED ]` | Context-dependent: crypto operations, string decoding, system information queries |
| `LOW` | `[LOW ]` | Likely benign: standard compiler output, string utilities, math helpers |

### MITRE ATT&CK Mapping

The AI maps each function to a MITRE ATT&CK technique where applicable. Common mappings you'll see:

| Technique | What it looks like in code |
|-----------|---------------------------|
| T1055 — Process Injection | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| T1547.001 — Registry Run Keys | `RegSetValueEx` targeting `HKCU\...\Run` |
| T1140 — Deobfuscate/Decode | XOR loops, base64 decode patterns |
| T1497.003 — Time-Based Evasion | `GetTickCount`, `NtQuerySystemTime` with sleep/compare |
| T1082 — System Information Discovery | `GetVersionEx`, `NtQuerySystemInformation` |
| T1059 — Command and Scripting | `CreateProcess` with `cmd.exe` / `powershell.exe` |
| T1071 — Application Layer Protocol | `WinHttpSendRequest`, `InternetConnect` |

### Follow-up Questions

The AI retains the full context of the current function across multiple questions. You don't need to repeat context — it knows which function you're asking about and what it has already told you.

---

## FLIRT Signature Matching

AIDebug uses a lightweight FLIRT-style matching approach to identify known library functions before running AI analysis. This prevents wasting API calls on `_memset`, `_strlen`, and CRT startup code that appears in every PE.

**How it works:**

1. **Import wrapper detection** — if a function is just `jmp [IAT_entry]`, it's identified by the imported function name
2. **CRC16 prologue match** — the first 32 instruction bytes (call targets zeroed out) are hashed and matched against `data/flirt_sigs.json`
3. **Single-import inference** — a function that calls exactly one imported API and returns immediately is named after that API
4. **Trivial stub detection** — functions with 3 or fewer instructions are marked as library stubs

**Effect on the function list:** Library functions show `[LIB ]` badge and the matched name (e.g., `_memset`, `malloc`). They are excluded from AI analysis by default.

**Force analysis:** To override and send a library function to AI anyway, use the `--force-ai` flag in CLI mode, or the analysis will run if you select the function in the TUI and it is not yet analyzed.

The signature database (`data/flirt_sigs.json`) currently covers msvcrt (memset/memcpy/strlen/malloc/CRT startup), zlib inflate/deflate, and several OpenSSL functions.

---

## Malware Pattern Detection

Before sending any function to AI, AIDebug runs a fast pattern scan across all instructions. Detected patterns are shown in the Patterns tab and injected into the AI prompt as context.

| Pattern | Severity | Detection logic |
|---------|----------|----------------|
| `xor_decryption_loop` | HIGH | Backward jump + XOR on memory operand |
| `stack_string` | MEDIUM | 4+ consecutive `mov byte ptr [esp+N]` instructions |
| `api_hash_resolution` | HIGH | ROR/ROL + XOR loop (shellcode API hash pattern) |
| `rdtsc_timing_check` | MEDIUM/HIGH | RDTSC instruction present (1 = MEDIUM, 2+ = HIGH) |
| `direct_syscall` | HIGH | SYSCALL / SYSENTER / INT 2E instruction |
| `nop_sled` | INFO | 5+ consecutive NOP instructions |
| `null_preserving_xor` | HIGH | test reg,reg → jz → xor pattern (common in shellcode) |
| `base64_alphabet_reference` | MEDIUM | Reference to a known Base64 character table string |

Patterns are stored in the `detected_patterns` table in the database and appear in the HTML report under each function.

---

## Control Flow Graph

For every function, a CFG is built from the disassembly by splitting at branch/jump/return boundaries into basic blocks. Successor/predecessor links are computed from conditional and unconditional branch targets.

**TUI (Patterns tab):** Text rendering with box-drawing characters, block instruction counts, and successor addresses.

**HTML report:** Each function's detail section includes an inline SVG CFG generated by `CFGSVGRenderer`. No external dependencies — the SVG is embedded directly in the HTML file.

The CFG is built from the already-disassembled `Function` object — no extra disk I/O. Functions with only one basic block (linear code) still show the CFG with a single block for completeness.

---

## Dynamic Mode Features

### Memory Diff

When a function is hooked via Frida, the JS hook captures 64 bytes at each pointer-valued register (edi, esi, ecx, rdx, rsi, rdi) at function entry. On exit, the same regions are read again. The before/after comparison is stored as a `MemoryDiff` and shown in the register panel:

```
REGISTERS / SNAPSHOT
  EAX   0x00000001    (1)
  ECX   0x0012fe80    (1245824)
  EDX   0x00000000    (0)
  ...
  Stack: 558bec5156578b7d08...

MEMORY DIFF (EDI → 0x0052a000)
  Before: 00 00 00 00 00 00 00 00
  After : 4d 5a 90 00 03 00 00 00   ← 8 bytes changed
  "MZ.."  — PE header written to buffer
```

The diff summary is also included in the AI prompt when the function is analyzed in dynamic mode.

### Unpacking Detection

`debugger/scripts/unpack_detector.js` hooks:
- `VirtualAlloc` — tracks allocations with PAGE_EXECUTE_READWRITE (0x40)
- `VirtualProtect` / `NtProtectVirtualMemory` — fires when a previously-writable region is made executable (RWX→R-X transition)

When an RWX→R-X transition is detected, the engine prints the region address, size, and an OEP hint (scanned by looking for `push ebp; mov ebp, esp` prologues in the newly-executable region). This tells you exactly where the unpacked code starts:

```
[Unpack] RWX allocation detected @ 0x00870000  size=65536
[Unpack] *** UNPACKING COMPLETE ***
[Unpack] Region : 0x00870000  size=65536
[Unpack] OEP hint: 0x00870010  new_protect=0x20
```

After detecting this, you can re-run static analysis on the dumped region or set a breakpoint at the OEP hint.

### Network Traffic Capture

`debugger/scripts/network_tracer.js` hooks:

**Winsock (ws2_32.dll):** `connect`, `send`, `recv`, `sendto`, `recvfrom`, `getaddrinfo`, `gethostbyname`

**WinInet (wininet.dll):** `InternetOpenUrl`, `HttpSendRequest`, `InternetReadFile`

For each event it captures:
- Event type and API name
- Remote IP and port (parsed from `sockaddr` struct)
- Hostname or URL
- Actual buffer bytes (up to 512 bytes as hex string)
- Buffer size

Events stream in real time to the Network tab in the TUI and are saved to the `network_events` table in the database. This gives you C2 protocol reconstruction without needing a separate network capture tool.

---

## Supported Binary Formats

| Format | Architecture | Notes |
|--------|-------------|-------|
| PE32 | x86 (32-bit) | Windows malware — main target |
| PE32+ | x86-64 (64-bit) | 64-bit Windows malware |
| PE32 | ARM32 | Mobile/embedded Windows |
| ELF | x86-64 | Linux malware |
| ELF | ARM / AArch64 | Linux IoT malware |
| ELF | RISC-V 64 | IoT botnets (Mirai variants) |

Packed binaries are detected via section entropy (> 7.0 triggers a packing warning). Static analysis will work but may show fewer functions. Use dynamic mode with the unpacking detector to recover the real code.

---

## Project Structure

```
AIDebug/
│
├── main.py                      # Entry point — CLI argument parsing, mode dispatch
├── config.py                    # API key, model, paths, analysis limits
├── requirements.txt
│
├── analysis/
│   ├── static_analyzer.py       # PE/ELF parsing (pefile + pyelftools)
│   │                            #   → BinaryInfo: arch, sections, imports, strings
│   ├── disassembler.py          # Capstone recursive-descent disassembler
│   │                            #   → Function: instructions, calls_to, strings_ref
│   │                            #   → Runs FLIRT + pattern enrichment after discovery
│   ├── ai_analyzer.py           # Claude API integration
│   │                            #   → AIAnalysis: name, summary, risk, MITRE, notes
│   ├── cfg.py                   # CFG builder + CFGTextRenderer + CFGSVGRenderer
│   ├── pattern_detector.py      # PatternDetector — 8 malware behavioral patterns
│   └── flirt.py                 # FlirtMatcher — library function identification
│
├── data/
│   └── flirt_sigs.json          # CRC16 FLIRT signature database (msvcrt, zlib, OpenSSL)
│
├── debugger/
│   ├── engine.py                # Frida attach/spawn/hook engine
│   │                            #   + unpack detector + network tracer loaders
│   ├── snapshot.py              # FunctionSnapshot + MemoryDiff data structures
│   └── scripts/
│       ├── tracer.js            # Frida JS — hooks 80+ Win32 APIs
│       ├── unpack_detector.js   # Frida JS — VirtualProtect RWX→RX detection
│       └── network_tracer.js    # Frida JS — Winsock/WinInet buffer capture
│
├── storage/
│   └── trace_store.py           # SQLite: sessions, function traces, API calls,
│                                #         network_events, detected_patterns
│
├── reporting/
│   ├── html_report.py           # Self-contained HTML report (CFG SVG + patterns)
│   ├── yara_generator.py        # YARA rule generation via AI
│   └── json_export.py           # JSON export (schema aidebug/session/v1)
│
└── ui/
    └── tui.py                   # Textual TUI — 3-panel layout
                                 #   Right panel: 4 tabs (AI/CFG/Patterns/Network)
```

---

## Configuration

All settings are in `config.py`:

```python
# Claude model to use
AI_MODEL = "claude-opus-4-6"

# Max tokens in AI response
AI_MAX_TOKENS = 2048

# Max functions to discover per binary
MAX_FUNCTIONS_TO_DISCOVER = 300

# Max instructions disassembled per function
MAX_INSTRUCTIONS_PER_FUNCTION = 250

# Max disassembly characters sent to AI (cost control)
MAX_DISASSEMBLY_CHARS = 3500

# Min string length for extraction
MIN_STRING_LENGTH = 5

# SQLite database path
DB_PATH = "/home/andrey/AIDebug/traces.db"
```

To switch to a faster/cheaper model for batch work, change `AI_MODEL` to `"claude-sonnet-4-6"`.

---

## Dynamic Mode Setup

### Linux + Wine (Windows PE)

Install Wine and Frida:

```bash
sudo apt install wine
pip install frida frida-tools
```

Run the target under Wine, then attach:

```bash
# Terminal 1 — start the malware in Wine (isolated VM recommended)
wine malware1.exe

# Terminal 2 — attach AIDebug to the Wine process
python main.py --binary malware1.exe --mode dynamic --pid $(pgrep -f malware1.exe)
```

Or let AIDebug spawn it directly:

```bash
python main.py --binary malware1.exe --mode dynamic
```

### Windows (native)

Install Frida:

```bash
pip install frida frida-tools
```

Run normally — no Wine needed:

```bash
python main.py --binary malware1.exe --mode dynamic
```

> **Important:** Always run inside a VM snapshot. Use a tool like FakeNet-NG or INetSim to intercept network connections before they reach the real internet. The network tracer will capture the raw bytes regardless of whether the connection succeeds.

### RISC-V / IoT ELF (QEMU)

For `malware3.exe` (RISC-V ELF) and similar IoT samples:

```bash
# Install QEMU RISC-V user-mode emulator
sudo apt install qemu-user

# Run the binary under QEMU
qemu-riscv64 malware3

# For debugging, use QEMU + GDB server
qemu-riscv64 -g 1234 malware3 &
gdb-multiarch -ex "target remote :1234" malware3
```

Static analysis (no dynamic mode) works immediately on RISC-V without any additional setup. Pattern detection and CFG work for all supported architectures.

---

## Database & Caching

AIDebug stores all analysis results in a SQLite database (`traces.db` by default).

**What is cached:**
- Every session (binary path, SHA256, architecture, timestamp)
- Every analyzed function (disassembly, AI analysis JSON, risk level, MITRE technique)
- Every Win32 API call captured in dynamic mode (module, function, arguments, return value)
- Every detected malware pattern (name, severity, evidence, function address)
- Every network event captured in dynamic mode (event type, IP, port, URL, data hex)

**Effect:** Re-running the tool on a previously analyzed binary loads all results instantly from the database. No API calls are made for already-analyzed functions.

**Searching past analyses:**

```python
from storage import TraceStore

store = TraceStore('traces.db')

# List sessions
sessions = store.list_sessions()

# Search for functions mentioning 'registry' in any session
results = store.search(session_id=1, query='registry')

# Get all API calls from a dynamic session
api_calls = store.get_api_calls(session_id=2)

# Get network events from a dynamic session
net_events = store.get_network_events(session_id=2)

# Get all detected patterns for a session
patterns = store.get_patterns(session_id=1)

# Get patterns for one specific function
fn_patterns = store.get_patterns(session_id=1, address=0x4015c2)

# Get risk summary
summary = store.get_risk_summary(session_id=1)
# {'CRITICAL': 1, 'HIGH': 3, 'MEDIUM': 4, 'LOW': 17}
```

---

## Sandbox Safety

**Never run malware samples outside of an isolated environment.**

Recommended setup:

| Layer | Tool |
|-------|------|
| VM hypervisor | KVM/QEMU or VirtualBox with snapshot |
| Network isolation | FakeNet-NG or INetSim — fake C2 responses, block real egress |
| Filesystem | Snapshot the VM before each run; revert after |
| Host isolation | No shared folders, no clipboard sharing with the host |

AIDebug itself only reads the binary file for static analysis. In dynamic mode, Frida is attached to the running process — which means the malware is actively executing. The network tracer will capture C2 traffic bytes but does not block connections — ensure your network is isolated before enabling dynamic mode.

---

## Troubleshooting

**`ANTHROPIC_API_KEY is not set`**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

**`pefile not installed` / `pyelftools not installed`**
```bash
pip install pefile pyelftools
```

**`Frida not available` in dynamic mode**
```bash
pip install frida frida-tools
```

**`Permission denied` when attaching Frida**
```bash
# Linux: allow ptrace
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

**`No functions found` on a packed binary**
The binary is likely packed. The entropy check will warn you (`[!] Possible packing`). Options:
- Run in dynamic mode — the unpacking detector will fire when the stub unpacks and transitions the region from RWX to R-X
- Use a dedicated unpacker (UPX, custom unpackers) before analysis

**All functions show `[LIB ]` badge**
The binary may be statically linked. FLIRT is matching most functions against CRT signatures. Use `--force-ai` to analyze a specific function anyway, or check `data/flirt_sigs.json` to review what signatures are loaded.

**TUI rendering issues**
```bash
# Ensure your terminal supports 256 colors
export TERM=xterm-256color
```

**AI returns `parse_error` as function name**
The model returned text instead of JSON. This can happen on very short or very unusual functions. The raw response is stored in `analysis.raw_response`. Try selecting the function again to re-trigger analysis.

**Network tab shows no events**
Network capture only works in dynamic mode (`--mode dynamic`). In static mode the Network tab will remain empty.

---

## License

MIT License. See `LICENSE` for details.

---

*Always analyze malware in a properly isolated sandbox. The authors take no responsibility for damage caused by running malware samples outside of a controlled environment.*
