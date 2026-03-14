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
  - [Session Management](#session-management)
- [TUI Interface Guide](#tui-interface-guide)
  - [Layout](#layout)
  - [Keyboard Shortcuts](#keyboard-shortcuts)
  - [Function List Panel](#function-list-panel)
  - [Disassembly Panel](#disassembly-panel)
  - [AI Analysis Panel](#ai-analysis-panel)
  - [Chat Bar](#chat-bar)
- [AI Analysis Output](#ai-analysis-output)
  - [Risk Levels](#risk-levels)
  - [MITRE ATT&CK Mapping](#mitre-attck-mapping)
  - [Follow-up Questions](#follow-up-questions)
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
- **Claude AI** — each function's disassembly and context is sent to Claude, which returns a structured explanation: name, summary, parameters, return value, behaviors, risk level, MITRE ATT&CK technique
- **Frida dynamic instrumentation** — optional runtime mode that hooks function entry/exit, captures real register and memory state, and logs Win32 API calls
- **Textual TUI** — three-panel terminal UI with live AI analysis and a built-in chat interface for follow-up questions
- **SQLite persistence** — all analyses are cached locally; re-running the same binary costs zero API calls

---

## Features

| Feature | Description |
|---|---|
| PE32 / PE64 / ELF analysis | Parses sections, imports, exports, strings, entropy |
| Recursive-descent disassembler | Follows CALL targets from entry point, builds call graph |
| AI function explanation | Name suggestion, summary, parameters, return value, behaviors |
| Risk classification | LOW / MEDIUM / HIGH / CRITICAL per function |
| MITRE ATT&CK mapping | Technique ID and name per function |
| AI chat | Ask follow-up questions about any function in context |
| Frida hooks | Runtime register/stack snapshots at function entry and exit |
| Win32 API tracer | Hooks 80+ APIs across kernel32, advapi32, ntdll, wininet, ws2_32, user32 |
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
3. Open the three-panel TUI
4. Wait for you to select a function — AI analysis runs on demand when you click/select one
5. Press `A` to batch-analyze all functions at once

### Static Analysis Mode (CLI / headless)

```bash
python main.py --binary <path> --no-tui
```

Useful for scripting or running on remote servers without a terminal. The tool iterates through all discovered functions, sends each to Claude, and prints the results to stdout. Previously analyzed functions are loaded from cache — no repeat API calls.

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
4. Resume the process
5. As functions execute, capture register/memory snapshots and send them to Claude along with the disassembly — giving richer analysis than static mode alone

All API calls and function traces are saved to the database.

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
┌─ AIDebug ─ malware1.exe │ PE32 x86 │ 25 functions │ SHA256: 8d3634a7... ──┐
├──────────────────────┬──────────────────────────────┬──────────────────────┤
│  FUNCTIONS           │  DISASSEMBLY                 │  AI ANALYSIS         │
│ ─────────────────── │ ───────────────────────────  │ ──────────────────── │
│  [CRIT] 0x40bcb8    │  0x0040bcb8: push  ebp       │  [CRIT] alloc_rwx    │
│  [HIGH] 0x4079b6    │  0x0040bcb9: mov   ebp,esp   │                      │
│  [HIGH] 0x40f013    │  0x0040bcbb: sub   esp,0x20  │  Summary:            │
│  [MED ] 0x4015c2    │  0x0040bcbe: push  esi       │  Allocates RWX mem   │
│  [LOW ] 0x401000    │  0x0040bcbf: mov   eax,[..] │  via NT syscall...   │
│  [LOW ] 0x4012e6    │  ...                         │                      │
│  [ -- ] 0x401a03    │                              │  Risk: CRITICAL      │
│  [ -- ] 0x401a2b    │  REGISTERS / SNAPSHOT        │  MITRE: T1055.001    │
│                      │  (static mode — no snapshot) │                      │
│                      │                              │  Behaviors:          │
│                      │                              │  • RWX allocation    │
│                      │                              │  • NT API evasion    │
├──────────────────────┴──────────────────────────────┴──────────────────────┤
│  Ask AI: _                                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
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

Risk badges before AI analysis show `[ -- ]`. After analysis they update in real time.

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

In dynamic mode, the lower sub-panel shows the register state captured at function entry/exit.

### AI Analysis Panel

Displays the Claude analysis for the selected function:

```
[CRIT] allocate_rwx_region

Summary:
This function calls NtAllocateVirtualMemory directly to allocate a
read-write-execute memory region. Use of the NT native API instead
of VirtualAlloc is a known hook evasion technique targeting EDR products.

MITRE ATT&CK: T1055.001 - Process Injection: DLL Injection

Parameters:
  size      (ULONG_PTR): Size of memory to allocate
  protect   (ULONG):     Protection flags (0x40 = PAGE_EXECUTE_READWRITE)

Return value:
  Pointer to allocated RWX buffer, or NULL on failure

Behaviors:
  • Dynamic NT API resolution
  • RWX memory allocation — shellcode staging
  • Bypasses VirtualAlloc hooks in EDR products

Notes:
  Check callers for WriteProcessMemory or CreateRemoteThread after this call.
```

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

## Supported Binary Formats

| Format | Architecture | Notes |
|--------|-------------|-------|
| PE32 | x86 (32-bit) | Windows malware — main target |
| PE32+ | x86-64 (64-bit) | 64-bit Windows malware |
| PE32 | ARM32 | Mobile/embedded Windows |
| ELF | x86-64 | Linux malware |
| ELF | ARM / AArch64 | Linux IoT malware |
| ELF | RISC-V 64 | IoT botnets (Mirai variants) |

Packed binaries are detected via section entropy (> 7.0 triggers a packing warning). Analysis will work but may show fewer functions until the unpacking stub runs in dynamic mode.

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
│   └── ai_analyzer.py           # Claude API integration
│                                #   → AIAnalysis: name, summary, risk, MITRE, notes
│
├── debugger/
│   ├── engine.py                # Frida attach/spawn/hook engine
│   ├── snapshot.py              # FunctionSnapshot data structure
│   └── scripts/
│       └── tracer.js            # Frida JS — hooks 80+ Win32 APIs
│
├── storage/
│   └── trace_store.py           # SQLite: sessions, function traces, API call log
│
└── ui/
    └── tui.py                   # Textual TUI — three panels + chat bar
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

> **Important:** Always run inside a VM snapshot. Use a tool like FakeNet-NG or INetSim to intercept network connections. Never run malware on a host you care about.

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

Static analysis (no dynamic mode) works immediately on RISC-V without any additional setup.

---

## Database & Caching

AIDebug stores all analysis results in a SQLite database (`traces.db` by default).

**What is cached:**
- Every session (binary path, SHA256, architecture, timestamp)
- Every analyzed function (disassembly, AI analysis JSON, risk level, MITRE technique)
- Every Win32 API call captured in dynamic mode (module, function, arguments, return value)

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

AIDebug itself only reads the binary file for static analysis. In dynamic mode, Frida is attached to the running process — which means the malware is actively executing. Ensure your sandbox is properly isolated before enabling dynamic mode.

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
- Run in dynamic mode — let the unpacking stub execute, then attach after unpacking completes
- Use a dedicated unpacker (UPX, custom unpackers) before analysis

**TUI rendering issues**
```bash
# Ensure your terminal supports 256 colors
export TERM=xterm-256color
```

**AI returns `parse_error` as function name**
The model returned text instead of JSON. This can happen on very short or very unusual functions. The raw response is stored in `analysis.raw_response`. Try selecting the function again to re-trigger analysis.

---

## License

MIT License. See `LICENSE` for details.

---

*Always analyze malware in a properly isolated sandbox. The authors take no responsibility for damage caused by running malware samples outside of a controlled environment.*
