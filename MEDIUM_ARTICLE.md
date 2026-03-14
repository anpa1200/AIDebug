# I Built an AI-Powered Malware Debugger That Explains Every Function It Sees

## How I combined Claude AI, Frida, and Capstone into a reverse engineering tool that talks back

---

Malware reverse engineering is one of the most skill-intensive jobs in security. You sit with IDA Pro or Ghidra, stare at unnamed functions full of obfuscated assembly, and try to build a mental model of what a threat actor's code is actually doing. It takes years to get fast at it.

I wanted to change that. So I built **AIDebug** — an open-source malware debugger that uses the Claude AI to analyze every function it encounters, explain what it does in plain English, assign a risk level, and map it to a MITRE ATT&CK technique. In real time.

This article walks you through what the tool does, how it works architecturally, and how to run it yourself on a real malware sample.

---

## The Problem With Traditional Malware Analysis

When you open a stripped Windows PE in a disassembler, you're greeted with hundreds of functions named `sub_401234`. Your job is to:

1. Read the assembly
2. Understand what each function does
3. Name it
4. Repeat — for hours

The bottleneck is not intelligence, it's throughput. An experienced analyst can only read assembly so fast. And when malware is packed, obfuscated, or uses indirect calls, even experienced analysts slow down dramatically.

AI doesn't replace the analyst — but it can act as an extremely fast co-pilot that reads assembly and gives you its interpretation in seconds, while you decide where to look next.

---

## What AIDebug Does

AIDebug is a Python tool that combines four things:

- **Static analysis** — PE/ELF parsing, section entropy, imports, strings
- **Capstone disassembly** — recursive-descent function discovery
- **Claude AI analysis** — each function's disassembly + context is sent to Claude, which returns a structured JSON explanation
- **Frida dynamic instrumentation** — optional runtime mode that hooks function entry/exit and captures real register/memory state

The UI is a Textual TUI (terminal user interface) with three panels:

```
┌────────────────────┬──────────────────────────────┬──────────────────────────┐
│ FUNCTIONS (25)     │ DISASSEMBLY                  │ AI ANALYSIS              │
│────────────────────│──────────────────────────────│──────────────────────────│
│ [CRIT] 0x40bcb8   │ 0x0040bcb8: push ebp         │ ▶ allocate_shellcode_mem │
│ [HIGH] 0x4079b6   │ 0x0040bcb9: mov  ebp,esp     │                          │
│ [MED ] 0x4015c2   │ 0x0040bcbb: sub  esp,0x20    │ SUMMARY:                 │
│ [LOW ] 0x401000   │ 0x0040bcbe: push esi         │ This function calls      │
│ ...                │ 0x0040bcbf: mov  eax,[ebp+8] │ NtAllocateVirtualMemory  │
│                    │ 0x0040bcc2: call 0x40efe6    │ to allocate RWX memory,  │
│                    │ ...                          │ consistent with shellcode │
│                    │                              │ injection staging.        │
│                    │                              │                          │
│                    │                              │ RISK: ■ CRITICAL         │
│                    │                              │ MITRE: T1055.001         │
└────────────────────┴──────────────────────────────┴──────────────────────────┘
  Ask AI: Why does it use Nt* instead of VirtualAlloc?
```

You can type follow-up questions at the bottom. The AI has full context of the function and the conversation history.

---

## Architecture Deep Dive

### Layer 1: Static Analysis

The `StaticAnalyzer` class handles PE and ELF files:

```python
from analysis import StaticAnalyzer

analyzer = StaticAnalyzer()
info = analyzer.analyze('malware1.exe')

print(info.arch)         # 'x86'
print(info.entry_point)  # 0x401780
print(info.imports)      # [ImportInfo(dll='KERNEL32.dll', functions=[...])]
```

For PE files it uses `pefile` to extract:
- Architecture and image base
- Section names, virtual addresses, and **entropy** (entropy > 7.0 flags likely packing)
- Import table (DLL + function names)
- Export table
- Both ASCII and UTF-16LE strings with virtual address mapping

For ELF files it uses `pyelftools` with full symbol table support — including RISC-V (useful for IoT malware like Mirai variants).

### Layer 2: Disassembler

The `Disassembler` class uses Capstone for disassembly and implements a recursive-descent function finder:

```python
from analysis import Disassembler

dis = Disassembler(info)
addresses = dis.discover_functions()  # returns [0x401000, 0x4012e6, ...]

func = dis.get_function(0x40bcb8)
print(func.disassembly_text)
print(func.strings_referenced)   # strings referenced by immediate addresses
print(func.calls_to)             # addresses this function calls
print(func.called_from)          # who calls this function
```

The function discovery algorithm:
1. Start at the PE entry point
2. For each CALL instruction, record the target address
3. Recursively disassemble each target that's in an executable section
4. Apply export names where known

String association works by checking if any MOV/LEA instruction in the function has an immediate value that matches the virtual address of a known string. This is surprisingly effective at finding format strings, registry keys, filenames, and URLs referenced by a function.

### Layer 3: AI Analysis

This is the core of the tool. For each function, we build a structured prompt:

```
BINARY INFO:
  File      : malware1.exe
  Arch      : x86 32-bit
  OS Target : Windows
  SHA256    : 8d3634a77504...

KNOWN IMPORTED APIs:
  KERNEL32.dll: WaitForSingleObject, DuplicateHandle, LoadLibraryA, ...
  ADVAPI32.dll: CryptImportKey, CryptReleaseContext, CryptDecrypt, ...
  Secur32.dll:  FreeContextBuffer, DecryptMessage, ...

FUNCTION ADDRESS: 0x40bcb8

DISASSEMBLY (31 instructions):
0x0040bcb8:  push     ebp
0x0040bcb9:  mov      ebp,esp
...
0x0040bce2:  push     0x40
0x0040bce4:  call     NtAllocateVirtualMemory
...

REFERENCED STRINGS:
  "NtAllocateVirtualMemory"

CROSS-REFERENCES:
  Called from : 0x401780
  Calls to    : 0x40efe6, 0x40f013
```

Claude returns a structured JSON response:

```json
{
  "suggested_name": "allocate_rwx_region",
  "summary": "This function resolves NtAllocateVirtualMemory dynamically and uses it to allocate a read-write-execute memory region. The use of the native NT API instead of the Win32 VirtualAlloc is a common evasion technique to bypass security product hooks on the higher-level API.",
  "parameters": [
    {"name": "size", "type": "ULONG_PTR", "description": "Size of memory region to allocate"},
    {"name": "protect", "type": "ULONG", "description": "Memory protection flags, likely 0x40 (PAGE_EXECUTE_READWRITE)"}
  ],
  "return_value": "Pointer to allocated memory region, or NULL on failure",
  "behaviors": [
    "Dynamic API resolution via direct NT syscall",
    "RWX memory allocation — shellcode staging indicator",
    "Bypasses VirtualAlloc hooks common in EDR products"
  ],
  "mitre_technique": "T1055.001 - Process Injection: Dynamic-link Library Injection",
  "risk_level": "CRITICAL",
  "notes": "Using Nt* instead of Win32 API is a deliberate hook evasion technique. Check callers for subsequent WriteProcessMemory or CreateRemoteThread calls."
}
```

That note at the end — *"Check callers for subsequent WriteProcessMemory"* — is the kind of contextual intelligence that saves an analyst 20 minutes of cross-referencing.

### Layer 4: Dynamic Instrumentation (Frida)

In dynamic mode, the tool spawns the binary (under Wine on Linux, or natively on Windows) and attaches Frida:

```python
from debugger import DebugEngine

engine = DebugEngine()
pid = engine.spawn('malware1.exe')

def on_exit(snapshot):
    print(f"Return value: {hex(snapshot.return_value)}")
    print(f"Register changes: {snapshot.memory_diff_summary}")
    # feed snapshot into AI analyzer for richer context

engine.hook_function(0x40bcb8, on_exit=on_exit)
engine.load_api_tracer()   # hooks 80+ Win32 APIs automatically
engine.resume()
```

The `tracer.js` Frida script hooks 80+ high-value Windows APIs across `kernel32.dll`, `advapi32.dll`, `ntdll.dll`, `wininet.dll`, `ws2_32.dll`, and `user32.dll`. Every call is logged with its arguments (strings are auto-dereferenced from pointers) and return value.

When dynamic mode is active, the AI gets both static disassembly *and* the actual runtime values — what was in the registers, what the stack looked like at entry, what the function returned. The analysis quality improves significantly.

### Layer 5: Persistence (SQLite)

Every analysis is cached in a local SQLite database. Re-running the tool on the same binary is instant — no repeat API calls to Claude. You can also search across sessions:

```python
from storage import TraceStore

store = TraceStore('traces.db')
results = store.search(session_id=1, query='registry')
# Returns all functions whose analysis mentions registry operations
```

---

## Running It On a Real Sample

Let me walk through what actually happened when I ran this on `malware1.exe`.

### Step 1: Static fingerprint

```
[*] Format   : PE x86 32-bit  (Windows)
[*] EntryPoint: 0x401780
[*] Sections  : ['.text', '.rdata', '.data', '.reloc', 'dhqj']
[*] Imports   : 89 functions from 8 DLLs
```

Immediate red flags:
- **Section `dhqj`** — non-standard section name, often used by custom packers
- **Imports**: `Secur32.dll` (SSP manipulation), `ADVAPI32.dll` with `CryptDecrypt`/`CryptImportKey`, `ntdll.dll` NT-native calls

### Step 2: Function discovery

25 functions found via recursive descent from the entry point. Already interesting — a packed binary often shows fewer functions before unpacking.

### Step 3: Key findings from AI analysis

The functions that stood out most:

**`0x40bcb8` — `allocate_shellcode_region` [CRITICAL]**
> Calls NtAllocateVirtualMemory directly (bypassing EDR hooks on VirtualAlloc) to allocate executable memory. The 0x40 protection constant is PAGE_EXECUTE_READWRITE.
> MITRE: T1055.001

**`0x4079b6` — `check_os_and_open_registry` [HIGH]**
> Queries the Windows version (checking for "Windows 11") and opens a registry key using the NT native API NtOpenKey. The FallbackGUID string suggests this function is involved in persistence — likely writing a GUID-keyed run key.
> MITRE: T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

**`0x4015c2` — `get_system_time_precise` [MEDIUM]**
> Calls NtQuerySystemTime for high-resolution timestamps. In malware context this is often used for timing-based sandbox detection (checking if execution was delayed by a sandbox) or for seeding a custom PRNG.
> MITRE: T1497.003 — Virtualization/Sandbox Evasion: Time Based Evasion

**`0x40f013` — `decode_config_blob` [HIGH]**
> Takes a buffer and a numeric key (852149723 seen in strings). XOR/ROT cipher pattern in the loop structure. Likely decoding an embedded C2 address or configuration blob.

Within minutes — without writing a single IDA script — we have a threat profile: RWX allocation via NT syscalls (evasion), registry persistence, sandbox detection via timing, and an encoded C2 config.

---

## Installation

```bash
git clone https://github.com/anpa1200/AIDebug
cd AIDebug
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

### Run in TUI mode

```bash
python main.py --binary /path/to/sample.exe
```

### Run in CLI mode (headless, good for scripting)

```bash
python main.py --binary sample.exe --no-tui
```

### Batch analyze all functions

Inside the TUI, press `A` to queue all functions for AI analysis simultaneously.

### Dynamic mode (requires Frida + Wine/Windows)

```bash
# Linux with Wine
python main.py --binary sample.exe --mode dynamic

# Attach to running process
python main.py --binary sample.exe --mode dynamic --pid 4521
```

### Check past sessions

```bash
python main.py --list-sessions
```

---

## Ask the AI Follow-Up Questions

One of the most useful features is the chat bar at the bottom of the TUI. With a function selected and analyzed, you can type questions like:

- *"What protection constant should I look for to confirm it's RWX?"*
- *"Why use NtAllocateVirtualMemory instead of VirtualAlloc?"*
- *"What should I look at next to confirm process injection?"*
- *"Write a Yara rule for this function's behavior"*

The AI has the full function context and conversation history. It answers in plain text. This is closer to having a senior analyst sitting next to you than using a static analysis tool.

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
└────────────────────┬───────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │ (static)            │ (dynamic, optional)
          ▼                     ▼
          │             ┌───────────────────────┐
          │             │  DebugEngine (Frida)  │
          │             │  → FunctionSnapshot:  │
          │             │    registers, stack,  │
          │             │    retval, API calls  │
          │             └───────────┬───────────┘
          │                         │
          ▼                         ▼
┌────────────────────────────────────────────────────────────┐
│  AIAnalyzer (Claude claude-opus-4-6)                        │
│  → AIAnalysis: name, summary, params, risk, MITRE, notes   │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  TraceStore (SQLite)  — caches analyses per session        │
└────────────────────┬───────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────┐
│  Textual TUI                                               │
│  ┌──────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │ Function │  │ Disassembly  │  │   AI Analysis       │  │
│  │   List   │  │   + Regs     │  │   + Chat Input      │  │
│  └──────────┘  └──────────────┘  └─────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

---

## What's Next

This is the first release. Planned additions:

**Analysis improvements**
- FLIRT signature matching — detect known library functions so the AI skips them
- CFG (control flow graph) visualization per function
- Automatic detection of common malware patterns (string decryption loops, XOR key extraction)

**Dynamic mode improvements**
- Memory diff display between function entry and exit
- Automatic unpacking detection (hook `VirtualProtect` → re-disassemble after RWX→RX transition)
- Network traffic capture correlated with function calls

**Reporting**
- Export full session as PDF or HTML report
- YARA rule generation from AI analysis
- JSON export for SIEM/SOAR integration

---

## Why Claude?

I tried several models for the structured JSON output. Claude was the only one that consistently:

1. Returns valid JSON without markdown fences leaking through
2. Correctly identifies subtle evasion techniques (NT API usage, timing checks)
3. Writes accurate MITRE ATT&CK technique mappings
4. Provides genuinely useful analyst notes, not just restating the disassembly
5. Handles follow-up questions with full context awareness

The `claude-opus-4-6` model in particular has strong assembly comprehension. It correctly identifies x86 calling conventions, recognizes common compiler idioms, and understands the difference between a compiler-generated prologue and a hand-written shellcode stub.

---

## Conclusion

AIDebug is not a replacement for IDA Pro or a seasoned reverse engineer. It's a force multiplier. The combination of fast static analysis, Frida-based runtime tracing, and Claude's contextual intelligence gives you a tool that can triage a new malware sample in minutes — telling you which functions are dangerous, what they do, and where to look next.

The full source is at **https://github.com/anpa1200/AIDebug**.

If you're working in threat intelligence, incident response, or malware research — try it on your next sample and let me know what you find.

---

*All analysis in this article was performed in an isolated VM environment on samples used for security research. Always analyze malware in a properly isolated sandbox.*

---

**Tags:** `malware-analysis` `reverse-engineering` `python` `security` `ai` `llm` `frida` `claude`
