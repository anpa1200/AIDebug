"""Curated x86/x64 lessons used by AIDebug's local learning mode."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Lesson:
    lesson_id: str
    title: str
    category: str
    assembly: str
    pseudocode: str
    explanation: str
    effects: str
    analyst_clue: str
    pitfall: str


def _lesson(
    lesson_id: str,
    title: str,
    category: str,
    assembly: str,
    pseudocode: str,
    explanation: str,
    effects: str,
    analyst_clue: str,
    pitfall: str,
) -> Lesson:
    return Lesson(
        lesson_id,
        title,
        category,
        assembly.strip(),
        pseudocode.strip(),
        explanation,
        effects,
        analyst_clue,
        pitfall,
    )


_LESSONS = (
    _lesson("mov-load", "MOV: load from memory", "data movement", "mov eax, [rcx]", "value = *(uint32_t *)rcx;", "Copies four bytes from the address in RCX into EAX.", "EAX changes; upper RAX is cleared; flags unchanged.", "Track where RCX came from and whether the address is readable.", "MOV copies a value; brackets mean dereference."),
    _lesson("mov-store", "MOV: store to memory", "data movement", "mov [rdx], eax", "*(uint32_t *)rdx = value;", "Copies the low 32 bits of RAX to the address in RDX.", "Memory changes; registers and flags unchanged.", "A store often reveals output buffers, object fields, or state mutation.", "Do not reverse the Intel-syntax destination and source operands."),
    _lesson("lea-address", "LEA: calculate an address", "data movement", "lea rax, [rcx+rdx*4]", "result = rcx + rdx * 4;", "Computes an effective address without reading memory.", "RAX changes; flags unchanged.", "Scaled indexes often reveal arrays and element widths.", "LEA does not dereference the bracketed expression."),
    _lesson("lea-arithmetic", "LEA: arithmetic idiom", "data movement", "lea eax, [ecx+ecx*4]", "result = value * 5;", "Compilers use LEA for addition and multiplication by small constants.", "EAX changes; flags unchanged.", "Check later use before deciding the result is a pointer.", "LEA is not always pointer construction."),
    _lesson("movzx", "MOVZX: zero extension", "data movement", "movzx eax, byte ptr [rcx]", "result = (uint8_t)*rcx;", "Loads a byte and fills the wider destination with zeros.", "EAX changes and clears upper RAX; flags unchanged.", "Zero extension is evidence for an unsigned value.", "Operand width is evidence about type, not proof."),
    _lesson("movsx", "MOVSX: sign extension", "data movement", "movsx eax, byte ptr [rcx]", "result = (int8_t)*rcx;", "Loads a byte and replicates its sign bit through EAX.", "EAX changes; flags unchanged.", "Sign extension often precedes signed comparisons or arithmetic.", "0xFF becomes -1, not 255, after sign extension."),
    _lesson("movsxd", "MOVSXD: 32-to-64 sign extension", "data movement", "movsxd rax, dword ptr [rcx]", "result = (int64_t)*(int32_t *)rcx;", "Sign-extends a 32-bit value to 64 bits.", "RAX changes; flags unchanged.", "Common in signed indexes and relative jump-table offsets.", "Do not treat the loaded dword as an unsigned address."),
    _lesson("xchg", "XCHG: exchange values", "data movement", "xchg eax, ebx", "tmp = a; a = b; b = tmp;", "Swaps two operands without a temporary register visible in assembly.", "Both operands change; flags unchanged.", "Memory XCHG can also imply atomic synchronization.", "Register XCHG alone does not imply locking."),
    _lesson("add", "ADD: addition", "arithmetic", "add eax, 4", "value += 4;", "Adds the source to the destination.", "Destination and arithmetic flags change.", "Repeated fixed increments may walk structures or buffers.", "The same instruction can represent integer or pointer arithmetic."),
    _lesson("sub", "SUB: subtraction", "arithmetic", "sub ecx, 1", "count -= 1;", "Subtracts the source from the destination.", "Destination and arithmetic flags change.", "A decrement followed by a conditional jump is a loop clue.", "Signedness comes from later branch use, not SUB alone."),
    _lesson("inc", "INC: increment", "arithmetic", "inc edx", "index++;", "Adds one without changing the carry flag.", "Destination and most arithmetic flags change; CF is preserved.", "Often advances indexes, counters, or pointers.", "INC and ADD 1 differ in their carry-flag effect."),
    _lesson("imul", "IMUL: signed multiplication", "arithmetic", "imul eax, ecx, 10", "result = value * 10;", "Multiplies ECX by ten and stores the low result in EAX.", "Destination changes; CF and OF report overflow.", "Scaling may be ordinary indexing, size calculation, or encoding.", "The mnemonic says signed, but low-bit results can match unsigned multiplication."),
    _lesson("xor-zero", "XOR: zeroing idiom", "bit operations", "xor eax, eax", "value = 0;", "XORing a register with itself efficiently clears it.", "EAX and flags change; upper RAX is cleared.", "Recognize this before interpreting XOR as decoding.", "A single XOR is not evidence of encryption or obfuscation."),
    _lesson("and-mask", "AND: mask bits", "bit operations", "and eax, 0xff", "value &= 0xff;", "Keeps only the low eight bits.", "Destination and logical flags change; CF and OF clear.", "Masks commonly isolate flags, fields, bytes, or alignment.", "A mask does not prove the source type."),
    _lesson("or-set", "OR: set bits", "bit operations", "or eax, 1", "value |= 1;", "Forces selected bits to one.", "Destination and logical flags change; CF and OF clear.", "Often enables option flags or changes memory protection values.", "Decode the constant in its API or structure context."),
    _lesson("not", "NOT: invert bits", "bit operations", "not eax", "value = ~value;", "Flips every bit in the operand.", "Destination changes; flags unchanged.", "May appear in masks, checksums, encoding, or boolean normalization.", "Bitwise NOT is different from logical negation."),
    _lesson("shl", "SHL: logical left shift", "shifts and rotations", "shl eax, 3", "value <<= 3;", "Moves bits left and fills low bits with zero.", "Destination and shift-related flags change.", "Often multiplies unsigned values by powers of two or packs fields.", "Overflow and discarded high bits may matter."),
    _lesson("shr", "SHR: logical right shift", "shifts and rotations", "shr eax, 1", "value = (uint32_t)value >> 1;", "Moves bits right and fills high bits with zero.", "Destination and shift-related flags change.", "Suggests unsigned division or bit extraction.", "For negative signed values SHR does not preserve the sign."),
    _lesson("sar", "SAR: arithmetic right shift", "shifts and rotations", "sar eax, 1", "value = (int32_t)value >> 1;", "Moves bits right while replicating the sign bit.", "Destination and shift-related flags change.", "Evidence of signed arithmetic or sign-preserving field work.", "SAR rounding is not identical to C signed division in every case."),
    _lesson("rol", "ROL: rotate left", "shifts and rotations", "rol eax, 7", "value = rotl32(value, 7);", "Rotates discarded high bits back into the low end.", "Destination, CF, and sometimes OF change.", "Repeated rotates with XOR/add may indicate hashes or encoders.", "Rotations also occur in ordinary optimized algorithms."),
    _lesson("ror", "ROR: rotate right", "shifts and rotations", "ror eax, 13", "value = rotr32(value, 13);", "Rotates low bits back into the high end.", "Destination, CF, and sometimes OF change.", "Common in API hashing, checksums, and cryptographic primitives.", "A rotate constant alone does not identify an algorithm."),
    _lesson("cmp-je", "CMP and JE: equality branch", "control flow", "cmp ecx, 7\nje equal_case", "if (value == 7) goto equal_case;", "CMP subtracts conceptually and JE branches when the zero flag is set.", "Flags change; operands do not.", "This pair is a direct clue for equality tests.", "CMP does not store the subtraction result."),
    _lesson("test-jz", "TEST and JZ: zero/bit test", "control flow", "test rax, rax\njz is_null", "if (value == 0) goto is_null;", "TEST performs a non-stored AND; testing a register with itself checks for zero.", "Logical flags change; operands do not.", "Often checks pointers, API return values, or flag masks.", "TEST is not a memory read unless an operand dereferences memory."),
    _lesson("call-ret", "CALL and RET: function transfer", "control flow", "call target\nret", "result = target(...);\nreturn result;", "CALL saves a return address and transfers control; RET consumes it.", "RSP and RIP change; ABI-volatile registers may change.", "Reconstruct argument registers and stack slots before the call.", "A call target name is evidence, not a complete behavioral conclusion."),
    _lesson("indirect-call", "Indirect CALL", "control flow", "call rax", "result = function_pointer(...);", "Transfers to an address computed at runtime.", "Control flow and ABI-visible state change.", "Trace the pointer through imports, callbacks, vtables, or dynamic resolution.", "Indirect calls are common in legitimate software."),
    _lesson("cmovz", "CMOVZ: branchless selection", "control flow", "cmp ecx, 7\ncmovz eax, edx", "if (value == 7) result = alternative;", "Conditionally copies without changing control flow.", "Destination changes only if ZF is set; flags remain from CMP.", "Optimized if-statements may have no conditional jump.", "Do not miss data-dependent control expressed as data movement."),
    _lesson("rep-movsb", "REP MOVSB: block copy", "string operations", "rep movsb", "memcpy(rdi, rsi, rcx);", "Copies RCX bytes from RSI to RDI on x64 when DF is clear.", "RSI, RDI, and RCX change; memory is written.", "Trace source, destination, count, and direction flag.", "On Windows x64 the surrounding code may move arguments into string-op registers first."),
    _lesson("rep-stosb", "REP STOSB: block fill", "string operations", "rep stosb", "memset(rdi, al, rcx);", "Stores AL repeatedly into the destination buffer.", "RDI, RCX, and memory change.", "Often initializes buffers or deliberately wipes data.", "A zero fill is not automatically anti-forensic wiping."),
    _lesson("scasb", "SCASB: scan bytes", "string operations", "repne scasb", "while (count-- && *ptr++ != al) {}", "Compares AL against bytes in memory while advancing or retreating RDI.", "RDI, RCX, and flags change.", "May implement strlen, memchr, parsing, or sentinel searches.", "Direction depends on DF; do not always assume forward scanning."),
    _lesson("syscall", "SYSCALL: enter the kernel", "system and debugging", "syscall", "result = operating_system_service(...);", "Transfers to the operating-system system-call handler.", "ABI-defined registers and flags change.", "Resolve the syscall number and target OS before naming behavior.", "Syscall numbers differ across operating systems and versions."),
    _lesson("int3", "INT3: breakpoint exception", "system and debugging", "int 3", "debug_break();", "Raises a breakpoint exception.", "Control transfers to an exception/debug handler.", "May be a debugger breakpoint, assertion, padding trap, or anti-analysis clue.", "INT3 alone does not prove anti-debugging."),
    _lesson("rdtsc-cpuid", "RDTSC and CPUID", "system and debugging", "cpuid\nrdtsc", "serialize_cpu();\nticks = read_timestamp_counter();", "Queries CPU state and reads a timestamp counter.", "Several architecture-defined registers change.", "Timing deltas can contribute to environment or debugger checks.", "Both instructions have legitimate profiling and feature-detection uses."),
    _lesson("if-else", "Recover an if/else", "high-level structures", "cmp ecx, 7\njne not_equal\nmov eax, 1\njmp done\nnot_equal:\nxor eax, eax\ndone:\nret", "return value == 7 ? 1 : 0;", "A conditional branch selects one of two assignments before paths rejoin.", "EAX and flags change.", "Find the branch, both successor blocks, and the join point.", "Optimized equivalents may use SETcc, CMOV, or arithmetic."),
    _lesson("counted-loop", "Recover a counted loop", "high-level structures", "xor eax, eax\nxor r8d, r8d\nloop_start:\ncmp r8d, edx\njae loop_end\nadd eax, [rcx+r8*4]\ninc r8d\njmp loop_start\nloop_end:\nret", "for (uint32_t i=0; i<count; i++) sum += values[i];", "Initialization, a bounds test, a body, an increment, and a backward jump form a loop.", "EAX accumulates; R8D indexes; flags drive JAE.", "JAE indicates an unsigned comparison here.", "A backward jump is a strong clue, not absolute proof of source syntax."),
    _lesson("array-index", "Recognize an array access", "high-level structures", "mov eax, [rcx+rdx*4]", "value = array[index];", "A scaled index selects four-byte elements from a base address.", "EAX changes; memory is read.", "Scale factors are useful provisional element-width evidence.", "The base could also be a table embedded in a structure."),
    _lesson("structure-field", "Recognize a structure field", "high-level structures", "mov rax, [rcx+0x20]", "value = object->field_20;", "A stable displacement from a recurring base suggests a field.", "RAX changes; memory is read.", "Collect all offsets used with the same base before defining a structure.", "One access is insufficient to prove an object layout."),
    _lesson("switch-table", "Recover a switch jump table", "high-level structures", "cmp ecx, 5\nja default_case\nlea rax, [rip+jump_table]\nmovsxd rdx, [rax+rcx*4]\nadd rdx, rax\njmp rdx", "switch (value) { /* cases 0..5 */ }", "A bounds check and indexed relative-offset table dispatch to case blocks.", "RAX/RDX and flags change; control transfers indirectly.", "Also consider state-machine or interpreter dispatch.", "The table entries are signed relative offsets in this pattern."),
    _lesson("function-frame", "Function prologue and epilogue", "high-level structures", "endbr64\npush rbp\nmov rbp, rsp\nsub rsp, 0x40\n...\nleave\nret", "function() { /* 0x40-byte stack frame */ }", "Creates and later destroys a traditional stack frame; ENDBR64 marks a CET indirect-branch target.", "RSP/RBP and stack memory change.", "Use unwind data too; optimized functions may omit this shape.", "ENDBR64 is not application logic or proof of packing."),
    _lesson("xor-decoder", "Small XOR decoding loop", "high-level structures", "xor edx, edx\ndecode_loop:\ncmp rdx, r8\njae decode_done\nxor byte ptr [rcx+rdx], 0x5a\ninc rdx\njmp decode_loop\ndecode_done:\nret", "for (size_t i=0; i<len; i++) buffer[i] ^= 0x5a;", "Transforms a bounded buffer in place with a one-byte XOR key.", "RDX, flags, and buffer bytes change.", "Inspect who produced and who consumes the transformed buffer.", "This may be configuration encoding, a fixture, or obfuscation—not necessarily malware."),
    _lesson("dynamic-api", "Dynamic API resolution", "Windows behavior", "call LoadLibraryW\nmov rcx, rax\nlea rdx, [rip+api_name]\ncall GetProcAddress\ncall rax", "module = LoadLibraryW(name);\nfn = GetProcAddress(module, api_name);\nfn(...);", "Loads a module, resolves a symbol, and calls through the returned pointer.", "Argument and return registers follow the Windows x64 ABI.", "Trace module name, API string/hash, returned pointer, and every consumer.", "Dynamic resolution is dual-use and common in plugins and compatibility code."),
    _lesson("allocate-execute", "Writable buffer to execution", "Windows behavior", "call VirtualAlloc\n... decode/copy ...\ncall VirtualProtect\ncall rax", "buffer = allocate_writable();\ndecode(buffer);\nmake_executable(buffer);\n((void(*)())buffer)();", "Data preparation followed by executable protection and indirect transfer is important behavioral evidence.", "Memory mappings, protection flags, and control flow change.", "Record size, bytes, protections, and exact transfer target.", "VirtualAlloc or VirtualProtect alone is not enough for a conclusion."),
    _lesson("remote-memory", "Cross-process memory chain", "Windows behavior", "call OpenProcess\ncall VirtualAllocEx\ncall WriteProcessMemory\ncall CreateRemoteThread", "process = OpenProcess(...);\nremote = VirtualAllocEx(process,...);\nWriteProcessMemory(process,remote,...);\nCreateRemoteThread(process,...,remote,...);", "The sequence can populate and execute memory in another process.", "Handles, remote addresses, copied bytes, and thread state are outputs.", "Determine the target process, access rights, content, protections, and start address.", "Debuggers, administration, and accessibility tools can use similar APIs."),
    _lesson("iat-thunk", "IAT call or tail-call thunk", "Windows internals", "jmp qword ptr [rip+__imp_CreateFileW]", "return CreateFileW(...);", "An import thunk forwards directly through an Import Address Table slot.", "Control transfers without a new return address.", "Recognize tail calls so the function is not mistaken for unrelated escaped flow.", "A JMP can be a legitimate tail call, not only an intra-function branch."),
    _lesson("peb-access", "TEB/PEB access", "Windows internals", "mov rax, gs:[0x60]", "peb = NtCurrentTeb()->ProcessEnvironmentBlock;", "Reads the common x64 PEB pointer through the thread environment block.", "RAX changes; memory is read through GS.", "Follow loader-list walks, name hashes, exports, and resolved pointers.", "PEB walking appears in packers, shellcode, compatibility code, and malware."),
)


def catalog() -> tuple[Lesson, ...]:
    return _LESSONS


def get_lesson(lesson_id: str) -> Lesson | None:
    normalized = lesson_id.strip().lower()
    return next((lesson for lesson in _LESSONS if lesson.lesson_id == normalized), None)


def find_lessons(query: str) -> tuple[Lesson, ...]:
    needle = query.strip().lower()
    if not needle or needle in {"list", "all"}:
        return _LESSONS
    return tuple(
        lesson
        for lesson in _LESSONS
        if needle in " ".join((lesson.lesson_id, lesson.title, lesson.category)).lower()
    )
