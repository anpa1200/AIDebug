"""Metadata for AIDebug's compiled, non-executed learning corpus."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Lesson:
    lesson_id: str
    title: str
    category: str
    function_name: str
    explanation: str
    effects: str
    analyst_clue: str
    pitfall: str


def _lesson(
    lesson_id: str,
    title: str,
    category: str,
    explanation: str,
    effects: str,
    analyst_clue: str,
    pitfall: str,
) -> Lesson:
    return Lesson(
        lesson_id=lesson_id,
        title=title,
        category=category,
        function_name=f"learn_{lesson_id.replace('-', '_')}",
        explanation=explanation,
        effects=effects,
        analyst_clue=analyst_clue,
        pitfall=pitfall,
    )


_LESSONS = (
    _lesson("load-u32", "Load a 32-bit value", "data movement", "Reads a value through a pointer.", "A register receives four bytes from memory.", "Trace the pointer's origin and readable range.", "A register value and a dereferenced value are different evidence."),
    _lesson("store-u32", "Store a 32-bit value", "data movement", "Writes a value through a pointer.", "Memory changes at the destination address.", "Stores reveal output buffers and state mutation.", "Intel assembly writes the destination operand first."),
    _lesson("array-index", "Index a 32-bit array", "data movement", "Reads one element using a base pointer and index.", "The effective address is scaled by element width.", "A scale of four is provisional evidence for 32-bit elements.", "The base may be a field or table, not necessarily an array."),
    _lesson("zero-extend", "Zero-extend an unsigned byte", "data movement", "Widens an unsigned byte without changing its value.", "The wider destination's upper bits become zero.", "Look for MOVZX or an equivalent mask.", "Width is type evidence, not definitive proof."),
    _lesson("sign-extend", "Sign-extend a signed byte", "data movement", "Widens a signed byte while preserving its sign.", "The sign bit is replicated into the wider result.", "Look for MOVSX before signed comparisons or arithmetic.", "The byte 0xff becomes -1, not 255."),
    _lesson("swap-values", "Swap two memory values", "data movement", "Exchanges two values using a temporary.", "Both pointed-to memory locations change.", "Track both reads before the two stores.", "The compiler is not required to emit XCHG."),
    _lesson("add", "Integer addition", "arithmetic", "Adds two signed 32-bit values.", "The return register and arithmetic flags may change.", "Later use determines whether the value is a count, pointer, or scalar.", "ADD does not establish the source-level type."),
    _lesson("subtract", "Integer subtraction", "arithmetic", "Subtracts the second value from the first.", "The destination and arithmetic flags may change.", "A subtraction near a branch can implement comparison or loop control.", "Signedness comes from surrounding operations."),
    _lesson("increment", "Increment a value", "arithmetic", "Adds one to an unsigned value.", "The return register changes.", "Compilers may choose ADD or LEA instead of INC.", "Source syntax cannot be recovered from one mnemonic."),
    _lesson("multiply", "Signed multiplication", "arithmetic", "Multiplies two signed 32-bit values.", "A product is returned; overflow semantics depend on context.", "Look for IMUL or shift/add strength reduction.", "Optimizers may remove an obvious multiply instruction."),
    _lesson("signed-divide", "Signed division", "arithmetic", "Divides a signed dividend by a signed divisor.", "Dividend setup and quotient registers follow the architecture ABI.", "On x86, sign extension before IDIV is an important clue.", "Division by zero and signed overflow remain caller constraints."),
    _lesson("unsigned-modulo", "Unsigned remainder", "arithmetic", "Returns the remainder of unsigned division.", "The remainder register becomes the function result.", "Distinguish DIV from IDIV and track dividend width.", "Modulo by a power of two may compile into a mask."),
    _lesson("and-mask", "Mask low bits", "bit operations", "Keeps only the low eight bits.", "High bits are cleared and logical flags may change.", "Masks often isolate fields, bytes, or alignment.", "A mask alone does not prove a variable's type."),
    _lesson("or-flags", "Set flag bits", "bit operations", "Combines a value with a flag mask.", "Selected bits are forced to one.", "Interpret constants in their structure or API context.", "OR is not automatically permission manipulation."),
    _lesson("xor-values", "XOR two values", "bit operations", "Combines two values with exclusive OR.", "The destination bits and logical flags may change.", "Repeated XOR over memory can indicate encoding or checksums.", "A single XOR is not proof of encryption."),
    _lesson("invert-bits", "Invert every bit", "bit operations", "Computes the bitwise complement.", "Every result bit is flipped.", "Common in masks, checksums, and encoders.", "Bitwise NOT differs from logical negation."),
    _lesson("shift-left", "Variable left shift", "shifts and rotations", "Shifts a value left by a bounded count.", "Low bits fill with zero and high bits are discarded.", "Can represent multiplication or bit-field packing.", "Discarded high bits may be significant."),
    _lesson("logical-right", "Logical right shift", "shifts and rotations", "Shifts an unsigned value right.", "High bits fill with zero.", "Often indicates unsigned division or bit extraction.", "It does not preserve the sign of negative values."),
    _lesson("arithmetic-right", "Arithmetic right shift", "shifts and rotations", "Shifts a signed value right while preserving its sign.", "High bits replicate the sign bit.", "SAR is evidence of signed arithmetic.", "Rounding can differ from source-level signed division."),
    _lesson("rotate-left", "Rotate a 32-bit value", "shifts and rotations", "Rotates bits left by seven positions.", "Discarded high bits re-enter at the low end.", "Rotates often appear in hashes and encoders.", "The compiler may recognize and emit a rotate mnemonic."),
    _lesson("equal", "Equality comparison", "comparisons", "Returns whether two values are equal.", "Flags or a condition-code byte feed the result.", "CMP plus SETcc is a common optimized shape.", "CMP does not store its subtraction result."),
    _lesson("signed-less", "Signed less-than comparison", "comparisons", "Compares two signed integers.", "Signed condition codes determine the boolean result.", "Distinguish JL/SETL from unsigned JB/SETB.", "The same bit patterns have different signed meanings."),
    _lesson("unsigned-below", "Unsigned less-than comparison", "comparisons", "Compares two unsigned integers.", "Carry-based condition codes determine the result.", "JB/SETB often indicates an unsigned bound check.", "Do not translate it as a signed comparison."),
    _lesson("select-value", "Conditional selection", "control flow", "Chooses one of two values.", "Control flow or a conditional move selects the return value.", "Optimizers may use CMOV instead of a branch.", "No branch does not mean no condition."),
    _lesson("absolute-value", "Absolute magnitude", "control flow", "Returns the unsigned magnitude of a signed value.", "A sign test and negation or branchless idiom form the result.", "Watch how the minimum signed value is represented.", "Negation overflow rules matter at the source level."),
    _lesson("minimum", "Choose the minimum", "control flow", "Returns the smaller signed value.", "A comparison selects one input.", "CMOV can encode this without branching.", "Confirm whether the comparison is signed."),
    _lesson("maximum", "Choose the maximum", "control flow", "Returns the larger signed value.", "A comparison selects one input.", "Check the condition code and operand order.", "Reversing CMP operands reverses the relation."),
    _lesson("clamp", "Clamp to a range", "control flow", "Constrains a value between lower and upper bounds.", "Two comparisons select a boundary or the original value.", "Identify all exits before reconstructing the range.", "Optimized code may combine branches and conditional moves."),
    _lesson("sum-array", "Sum an array", "loops and arrays", "Accumulates all 32-bit array elements.", "An index/pointer advances while an accumulator changes.", "Find initialization, bound, body, and back edge.", "Pointer iteration and index iteration can decompile differently."),
    _lesson("find-value", "Search an array", "loops and arrays", "Returns the first matching index or -1.", "A loop comparison creates success and failure exits.", "Track signed sentinel values separately from size_t indexes.", "The decompiler's inferred return type may be provisional."),
    _lesson("count-nonzero", "Count matching bytes", "loops and arrays", "Counts nonzero bytes in a bounded buffer.", "Each comparison contributes zero or one to a counter.", "SETcc may feed arithmetic directly.", "A boolean-producing instruction is still data flow."),
    _lesson("copy-bytes", "Copy a byte buffer", "memory loops", "Copies bytes from source to destination.", "The source is read and destination is written for each element.", "Recover source, destination, count, and overlap assumptions.", "A loop may be a compiler expansion rather than a library call."),
    _lesson("fill-bytes", "Fill a byte buffer", "memory loops", "Writes the same byte across a bounded destination.", "Memory changes while a counter or pointer advances.", "Compilers may emit a loop, STOS, or a memset call.", "A zero fill is not automatically anti-forensic wiping."),
    _lesson("string-length", "Measure a C string", "memory loops", "Scans until a zero terminator.", "A pointer/index advances and bytes are compared with zero.", "Recognize sentinel loops and unbounded caller assumptions.", "The input must be terminated in accessible memory."),
    _lesson("xor-buffer", "Transform a buffer with XOR", "reverse-engineering patterns", "XORs every byte with a key in place.", "The buffer and loop state change.", "Inspect producers and consumers of the transformed bytes.", "This is dual-use encoding, not automatically malware."),
    _lesson("checksum", "Compute a rolling checksum", "reverse-engineering patterns", "Combines every byte into a rolling 32-bit state.", "Shift/add/subtract operations update the accumulator.", "Identify constants and loop boundaries before naming an algorithm.", "Similar instruction shapes can represent hashes or ordinary indexing."),
    _lesson("fibonacci", "Iterative state machine", "loops and arrays", "Updates two dependent state values across a counted loop.", "Multiple registers rotate through previous/current/next roles.", "Use data dependencies rather than register names to assign roles.", "Compiler register allocation can obscure source variables."),
    _lesson("factorial", "Multiplicative loop", "loops and arrays", "Multiplies a descending sequence of values.", "An accumulator grows while the loop variable decreases.", "A backward edge plus compare reveals the loop boundary.", "Overflow is possible even when the control flow is clear."),
    _lesson("switch-dispatch", "Switch dispatch", "high-level structures", "Selects one of several arithmetic operations.", "A bounds check and branches or a table route control.", "Look for jump tables, value tables, or comparison trees.", "A switch is not guaranteed to compile as an indirect jump."),
    _lesson("structure-fields", "Read structure fields", "high-level structures", "Reads fields at stable offsets from one base pointer.", "Several memory loads use related displacements.", "Collect every offset before defining a structure.", "One function may expose only part of the layout."),
    _lesson("indirect-call", "Call a function pointer", "calls and ABI", "Invokes a caller-supplied function pointer.", "Arguments are prepared, then control transfers indirectly.", "Trace the pointer through callbacks, tables, or imports.", "Indirect calls are common in legitimate software."),
    _lesson("recursive-sum", "Recursive function", "calls and ABI", "Calls itself with a smaller argument until a base case.", "Each call creates ABI-visible input and return state.", "Identify the base case and recurrence separately.", "Optimizers may turn recursion into a loop."),
    _lesson("byte-swap", "Reverse byte order", "bit operations", "Reorders the four bytes of a 32-bit value.", "Masks and shifts, or a BSWAP instruction, produce the result.", "Recognize endian conversion idioms.", "Byte order is a representation issue, not encryption."),
    _lesson("dot-product", "Multiply and accumulate", "loops and arrays", "Multiplies paired array elements and accumulates a 64-bit sum.", "Two indexed reads, a multiply, and a wide accumulator repeat.", "Check operand extension before assigning signedness.", "Optimized builds may vectorize this shape."),
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
        if needle
        in " ".join(
            (lesson.lesson_id, lesson.function_name, lesson.title, lesson.category)
        ).lower()
    )
