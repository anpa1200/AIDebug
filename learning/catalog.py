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
    _lesson("mov-load", "MOV: load from memory", "data movement", "Reads a 32-bit value through a pointer.", "A register receives four bytes from memory.", "Trace the pointer's origin and readable range.", "A register value and a dereferenced value are different evidence."),
    _lesson("mov-store", "MOV: store to memory", "data movement", "Writes a 32-bit value through a pointer.", "Memory changes at the destination address.", "Stores reveal output buffers and state mutation.", "Intel assembly writes the destination operand first."),
    _lesson("lea-address", "LEA: calculate an address", "data movement", "Calculates the address of one array element without reading it.", "A scaled effective address becomes the return value; flags are unchanged.", "Scaled indexes reveal provisional element widths.", "LEA calculates an address expression but does not dereference it."),
    _lesson("lea-arithmetic", "LEA: arithmetic expression", "data movement", "Multiplies an integer by five through an expression a compiler can encode with LEA.", "The destination changes without arithmetic flags changing.", "Check later use before deciding an LEA result is a pointer.", "LEA is not only a pointer-loading instruction."),
    _lesson("movzx", "MOVZX: zero-extend a byte", "data movement", "Widens an unsigned byte without changing its value.", "The wider destination's upper bits become zero.", "Look for MOVZX or an equivalent mask.", "Width is type evidence, not definitive proof."),
    _lesson("movsx", "MOVSX: sign-extend a byte", "data movement", "Widens a signed byte while preserving its sign.", "The sign bit is replicated into the wider result.", "Look for MOVSX before signed comparisons or arithmetic.", "The byte 0xff becomes -1, not 255."),
    _lesson("movsxd", "MOVSXD: sign-extend 32 to 64 bits", "data movement", "Widens a signed 32-bit integer to 64 bits.", "The source sign bit is replicated across the upper 32 bits.", "Common in signed indexes and relative jump-table offsets.", "Do not interpret the source dword as an unsigned address."),
    _lesson("xchg", "XCHG: exchange register values", "data movement", "Uses explicit inline assembly so the compiled case contains a real XCHG instruction.", "Both selected registers change; flags are unchanged.", "Memory XCHG has additional atomic semantics.", "A normal C swap is not guaranteed to compile to XCHG."),
    _lesson("array-index", "Index a 32-bit array", "data movement", "Reads one element using a base pointer and index.", "The effective address is scaled by element width.", "A scale of four is provisional evidence for 32-bit elements.", "The base may be a field or table, not necessarily an array."),
    _lesson("add", "Integer addition", "arithmetic", "Adds two signed 32-bit values.", "The return register and arithmetic flags may change.", "Later use determines whether the value is a count, pointer, or scalar.", "ADD does not establish the source-level type."),
    _lesson("subtract", "Integer subtraction", "arithmetic", "Subtracts the second value from the first.", "The destination and arithmetic flags may change.", "A subtraction near a branch can implement comparison or loop control.", "Signedness comes from surrounding operations."),
    _lesson("increment", "Increment a value", "arithmetic", "Adds one to an unsigned value.", "The return register changes.", "Compilers may choose ADD or LEA instead of INC.", "Source syntax cannot be recovered from one mnemonic."),
    _lesson("negate", "Negate an integer", "arithmetic", "Computes the two's-complement negation of an unsigned value.", "The destination changes and a NEG instruction updates arithmetic flags.", "NEG often appears in sign handling, subtraction idioms, and index calculations.", "Negation alone does not prove that the source value was signed."),
    _lesson("multiply", "Signed multiplication", "arithmetic", "Multiplies two signed 32-bit values.", "A product is returned; overflow semantics depend on context.", "Look for IMUL or shift/add strength reduction.", "Optimizers may remove an obvious multiply instruction."),
    _lesson("signed-divide", "Signed division", "arithmetic", "Divides a signed dividend by a signed divisor.", "Dividend setup and quotient registers follow the architecture ABI.", "On x86, sign extension before IDIV is an important clue.", "Division by zero and signed overflow remain caller constraints."),
    _lesson("unsigned-modulo", "Unsigned remainder", "arithmetic", "Returns the remainder of unsigned division.", "The remainder register becomes the function result.", "Distinguish DIV from IDIV and track dividend width.", "Modulo by a power of two may compile into a mask."),
    _lesson("saturating-add", "Saturating unsigned addition", "arithmetic", "Adds two values and clamps overflow to UINT32_MAX.", "The sum and carry-style comparison select the result.", "A result smaller than an operand is an unsigned-overflow clue.", "Saturation is not ordinary wrapping arithmetic."),
    _lesson("average-pair", "Overflow-safe average", "arithmetic", "Computes the average of two unsigned values without overflowing their sum.", "AND, XOR, and shift operations combine shared and differing bits.", "Bitwise arithmetic can implement familiar numeric operations.", "Do not label every XOR-and-shift sequence as encoding."),
    _lesson("and-mask", "Mask low bits", "bit operations", "Keeps only the low eight bits.", "High bits are cleared and logical flags may change.", "Masks often isolate fields, bytes, or alignment.", "A mask alone does not prove a variable's type."),
    _lesson("or-flags", "Set flag bits", "bit operations", "Combines a value with a flag mask.", "Selected bits are forced to one.", "Interpret constants in their structure or API context.", "OR is not automatically permission manipulation."),
    _lesson("xor-values", "XOR two values", "bit operations", "Combines two values with exclusive OR.", "The destination bits and logical flags may change.", "Repeated XOR over memory can indicate encoding or checksums.", "A single XOR is not proof of encryption."),
    _lesson("invert-bits", "Invert every bit", "bit operations", "Computes the bitwise complement.", "Every result bit is flipped.", "Common in masks, checksums, and encoders.", "Bitwise NOT differs from logical negation."),
    _lesson("test-bit", "Test masked bits", "bit operations", "Returns whether any bit selected by a mask is set.", "A logical test updates condition flags without preserving the temporary AND result.", "TEST followed by SETcc or Jcc commonly implements flags and capability checks.", "A tested mask needs surrounding structure or API context before it can be named."),
    _lesson("bit-clear", "Clear selected bits", "bit operations", "Clears every bit selected by a caller-supplied mask.", "The mask is inverted before AND combines it with the value.", "AND with a complemented mask often removes flags or permissions.", "The mask's meaning still requires context."),
    _lesson("bit-toggle", "Toggle selected bits", "bit operations", "Flips every bit selected by a mask.", "XOR changes selected bits and leaves all others unchanged.", "Compare the mask with constants or structure definitions.", "A single XOR is ordinary bit manipulation, not encryption."),
    _lesson("extract-field", "Extract a bit field", "bit operations", "Extracts an eight-bit field beginning at bit 8.", "A right shift and mask isolate the field.", "Shift-plus-mask pairs reveal packed layout candidates.", "Field width is evidence, not a recovered type definition."),
    _lesson("insert-field", "Insert a bit field", "bit operations", "Replaces an eight-bit field while preserving neighboring bits.", "A clear-mask removes the old field before OR inserts the new value.", "Repeated masks and shifts can reveal serialized layouts.", "Confirm bit numbering and endianness separately."),
    _lesson("parity-fold", "Fold bits to parity", "bit operations", "Folds a 32-bit value until one parity bit remains.", "Repeated XOR shifts combine distant bits.", "XOR-folding shapes appear in checksums and bit tests.", "Parity is not a cryptographic hash."),
    _lesson("power-of-two", "Detect a power of two", "bit operations", "Checks the classic value AND value-minus-one identity.", "Subtraction, AND, and a zero test produce the result.", "This idiom often validates sizes, alignments, or ring buffers.", "Zero needs a separate check."),
    _lesson("align-up", "Align a value upward", "bit operations", "Rounds a value up to a caller-provided power-of-two alignment.", "Addition and an inverted mask clear low address bits.", "Alignment masks often appear around allocation and section parsing.", "The formula assumes a suitable nonzero alignment."),
    _lesson("crc-step", "CRC-style bit step", "bit operations", "Runs eight conditional polynomial updates over a 32-bit state.", "Right shifts and conditional XOR update the state.", "Polynomial constants are strong algorithm-family clues.", "One step does not identify the complete CRC variant."),
    _lesson("shift-left", "Variable left shift", "shifts and rotations", "Shifts a value left by a bounded count.", "Low bits fill with zero and high bits are discarded.", "Can represent multiplication or bit-field packing.", "Discarded high bits may be significant."),
    _lesson("logical-right", "Logical right shift", "shifts and rotations", "Shifts an unsigned value right.", "High bits fill with zero.", "Often indicates unsigned division or bit extraction.", "It does not preserve the sign of negative values."),
    _lesson("arithmetic-right", "Arithmetic right shift", "shifts and rotations", "Shifts a signed value right while preserving its sign.", "High bits replicate the sign bit.", "SAR is evidence of signed arithmetic.", "Rounding can differ from source-level signed division."),
    _lesson("rotate-left", "Rotate a 32-bit value", "shifts and rotations", "Rotates bits left by seven positions.", "Discarded high bits re-enter at the low end.", "Rotates often appear in hashes and encoders.", "The compiler may recognize and emit a rotate mnemonic."),
    _lesson("rotate-right", "Rotate right by a variable count", "shifts and rotations", "Rotates a 32-bit value right by a caller-supplied bounded count.", "Low bits re-enter at the high end instead of being discarded.", "Variable rotates are common in hashes, checksums, and compact decoders.", "A rotate is an algorithm clue, not proof of cryptography."),
    _lesson("equal", "Equality comparison", "comparisons", "Returns whether two values are equal.", "Flags or a condition-code byte feed the result.", "CMP plus SETcc is a common optimized shape.", "CMP does not store its subtraction result."),
    _lesson("signed-less", "Signed less-than comparison", "comparisons", "Compares two signed integers.", "Signed condition codes determine the boolean result.", "Distinguish JL/SETL from unsigned JB/SETB.", "The same bit patterns have different signed meanings."),
    _lesson("unsigned-below", "Unsigned less-than comparison", "comparisons", "Compares two unsigned integers.", "Carry-based condition codes determine the result.", "JB/SETB often indicates an unsigned bound check.", "Do not translate it as a signed comparison."),
    _lesson("zero-check", "Compare with zero", "comparisons", "Returns whether a value is zero.", "TEST or CMP feeds a zero-condition result.", "Compilers commonly prefer TEST reg,reg for zero checks.", "A zero value may mean null, false, empty, or a numeric zero."),
    _lesson("not-equal", "Inequality comparison", "comparisons", "Returns whether two values differ.", "A comparison feeds SETNE or a conditional branch.", "Track both operand order and width.", "Not-equal does not reveal signedness."),
    _lesson("signed-greater", "Signed greater-than comparison", "comparisons", "Compares two signed 32-bit integers.", "Signed condition codes select the boolean result.", "JG or SETG uses signed overflow and sign evidence.", "Do not confuse it with unsigned JA."),
    _lesson("unsigned-above", "Unsigned greater-than comparison", "comparisons", "Compares two unsigned 32-bit integers.", "Carry and zero conditions determine the result.", "JA or SETA is evidence of an unsigned relation.", "The same bits may represent a negative signed value."),
    _lesson("range-check", "Inclusive range check", "comparisons", "Tests whether a value lies between two inclusive unsigned bounds.", "Two relations combine into one boolean result.", "Subtraction-based range idioms may collapse both comparisons.", "Confirm whether each endpoint is inclusive."),
    _lesson("select-value", "Conditional selection", "control flow", "Chooses one of two values.", "Control flow or a conditional move selects the return value.", "Optimizers may use CMOV instead of a branch.", "No branch does not mean no condition."),
    _lesson("absolute-value", "Absolute magnitude", "control flow", "Returns the unsigned magnitude of a signed value.", "A sign test and negation or branchless idiom form the result.", "Watch how the minimum signed value is represented.", "Negation overflow rules matter at the source level."),
    _lesson("minimum", "Choose the minimum", "control flow", "Returns the smaller signed value.", "A comparison selects one input.", "CMOV can encode this without branching.", "Confirm whether the comparison is signed."),
    _lesson("maximum", "Choose the maximum", "control flow", "Returns the larger signed value.", "A comparison selects one input.", "Check the condition code and operand order.", "Reversing CMP operands reverses the relation."),
    _lesson("clamp", "Clamp to a range", "control flow", "Constrains a value between lower and upper bounds.", "Two comparisons select a boundary or the original value.", "Identify all exits before reconstructing the range.", "Optimized code may combine branches and conditional moves."),
    _lesson("do-while", "Post-tested loop", "control flow", "Counts how many right shifts are needed to reduce a value to zero, executing the body at least once.", "The loop body changes both the value and counter before testing the exit condition.", "A backward branch whose condition follows the body is evidence for a do-while loop.", "Do not automatically reconstruct every backward branch as a pre-tested while loop."),
    _lesson("logical-and", "Short-circuit logical AND", "control flow", "Returns true only when both inputs are nonzero.", "The second condition may be evaluated only after the first succeeds.", "Multiple tests converging on one false exit suggest short-circuit AND.", "Optimizers may remove the visible branch structure."),
    _lesson("logical-or", "Short-circuit logical OR", "control flow", "Returns true when either input is nonzero.", "The first successful condition can bypass the second test.", "Shared true exits often reveal short-circuit OR.", "Bitwise OR and logical OR have different result semantics."),
    _lesson("logical-not", "Logical negation", "control flow", "Converts zero to one and every nonzero value to zero.", "A zero test materializes a normalized boolean.", "SETE after TEST is a common branchless form.", "Logical NOT differs from bitwise complement."),
    _lesson("ternary-negate", "Conditional negation", "control flow", "Selects a value or its two's-complement negation from a flag.", "A test and branch or conditional move select the result.", "Conditional arithmetic may compile without a visible branch.", "The flag is not necessarily a source-language bool."),
    _lesson("early-return", "Early return", "control flow", "Returns a fallback immediately for zero input and otherwise transforms the value.", "One condition creates separate short and computed exits.", "Recover all return sites before naming the function.", "Decompiler structure can hide multiple machine-code exits."),
    _lesson("state-machine", "Small state machine", "control flow", "Updates a state according to a bounded stream of input symbols.", "A loop repeatedly dispatches branches based on current state and input.", "State variables plus repeated dispatch are parser or protocol clues.", "A switch inside a loop is not automatically obfuscation."),
    _lesson("sum-array", "Sum an array", "loops and arrays", "Accumulates all 32-bit array elements.", "An index/pointer advances while an accumulator changes.", "Find initialization, bound, body, and back edge.", "Pointer iteration and index iteration can decompile differently."),
    _lesson("find-value", "Search an array", "loops and arrays", "Returns the first matching index or -1.", "A loop comparison creates success and failure exits.", "Track signed sentinel values separately from size_t indexes.", "The decompiler's inferred return type may be provisional."),
    _lesson("count-nonzero", "Count matching bytes", "loops and arrays", "Counts nonzero bytes in a bounded buffer.", "Each comparison contributes zero or one to a counter.", "SETcc may feed arithmetic directly.", "A boolean-producing instruction is still data flow."),
    _lesson("binary-search", "Binary search", "loops and arrays", "Searches a sorted signed-integer array by repeatedly halving the candidate range.", "Low, high, and midpoint state converge until a match or empty range is reached.", "Midpoint arithmetic and two range updates distinguish binary search from a linear scan.", "Signed element comparison and unsigned array indexes coexist in this function."),
    _lesson("counted-down-loop", "Count-down loop", "loops and arrays", "Accumulates a descending sequence until the counter reaches zero.", "The counter decreases on each backward edge.", "A decrement followed by a nonzero branch is a classic loop shape.", "The original source may have used for, while, or do-while syntax."),
    _lesson("nested-loop", "Nested counted loops", "loops and arrays", "Combines row and column counters across two loop levels.", "Two backward edges maintain separate induction variables.", "Identify the inner loop boundary before reconstructing the outer loop.", "Optimizers may flatten or interchange loops."),
    _lesson("sum-matrix", "Sum a row-major matrix", "loops and arrays", "Sums a bounded matrix represented as a flat row-major array.", "Nested indexes generate scaled row and column addressing.", "Row stride arithmetic reveals likely dimensions.", "A flat allocation may still represent multidimensional data."),
    _lesson("matrix-index", "Calculate a matrix element", "loops and arrays", "Reads one row-major matrix element using row, column, and width.", "Multiply-add index arithmetic feeds a scaled memory read.", "Recover the stride before assigning dimensions.", "The width argument is not necessarily the allocated row length."),
    _lesson("prefix-sum", "Build prefix sums", "loops and arrays", "Replaces each array element with the cumulative sum through that position.", "An accumulator and each destination element change together.", "Loop-carried state distinguishes prefix transforms from independent mapping.", "In-place mutation changes later reads."),
    _lesson("difference-array", "Calculate adjacent differences", "loops and arrays", "Writes the difference between each adjacent pair of input values.", "Two neighboring reads feed each output element.", "Related base-plus-index accesses can reveal windowed processing.", "Source and destination overlap assumptions matter."),
    _lesson("find-maximum", "Find an array maximum", "loops and arrays", "Scans signed values and retains the largest observed element.", "A comparison conditionally updates a loop-carried candidate.", "Conditional moves often implement min/max updates.", "Check the empty-input behavior before defining the contract."),
    _lesson("find-minimum", "Find an array minimum", "loops and arrays", "Scans signed values and retains the smallest observed element.", "A comparison conditionally updates a loop-carried candidate.", "Operand order distinguishes minimum from maximum.", "Signed and unsigned minima use different conditions."),
    _lesson("count-byte", "Count a target byte", "loops and arrays", "Counts occurrences of one byte in a bounded buffer.", "Byte comparisons feed a counter across the loop.", "SETcc may be added directly into the count.", "A byte histogram primitive is not inherently suspicious."),
    _lesson("find-byte", "Find a target byte", "loops and arrays", "Returns the first matching byte index or -1.", "The loop has match and exhaustion exits.", "Byte scanning resembles memchr even when inlined.", "The sentinel return type may be misinferred."),
    _lesson("lookup-table", "Indexed table lookup", "loops and arrays", "Masks an index and reads one entry from a 256-element table.", "A bounded index feeds a scaled memory access.", "Table access can implement substitution, parsing, or classification.", "A lookup table is not automatically cryptographic."),
    _lesson("copy-bytes", "Copy a byte buffer", "memory loops", "Copies bytes from source to destination.", "The source is read and destination is written for each element.", "Recover source, destination, count, and overlap assumptions.", "A loop may be a compiler expansion rather than a library call."),
    _lesson("fill-bytes", "Fill a byte buffer", "memory loops", "Writes the same byte across a bounded destination.", "Memory changes while a counter or pointer advances.", "Compilers may emit a loop, STOS, or a memset call.", "A zero fill is not automatically anti-forensic wiping."),
    _lesson("string-length", "Measure a C string", "memory loops", "Scans until a zero terminator.", "A pointer/index advances and bytes are compared with zero.", "Recognize sentinel loops and unbounded caller assumptions.", "The input must be terminated in accessible memory."),
    _lesson("reverse-buffer", "Reverse a byte buffer", "memory loops", "Swaps bytes from the two ends of a bounded buffer until the pointers meet.", "Two indexes move toward each other while paired memory locations are read and written.", "Opposing pointer movement often reveals reversal, parsing, or in-place transformation.", "An in-place byte swap is not by itself evidence of obfuscation."),
    _lesson("compare-buffers", "Compare byte buffers", "memory loops", "Lexicographically compares two bounded byte buffers.", "Paired reads continue until a difference or the bound is reached.", "A mismatch exit plus unsigned byte subtraction resembles memcmp.", "Equality-only callers may ignore the sign of the result."),
    _lesson("reverse-copy", "Copy bytes in reverse order", "memory loops", "Writes a reversed copy while leaving the source unchanged.", "One index advances while the source index moves backward.", "Opposing source and destination directions reveal reordering.", "This differs from in-place reversal and has different aliasing risks."),
    _lesson("copy-words", "Copy 32-bit words", "memory loops", "Copies a bounded sequence of 32-bit elements.", "Scaled loads and stores advance by four-byte elements.", "Operand width and stride jointly support an element-size inference.", "The values may still be packed fields rather than integers."),
    _lesson("zero-words", "Zero 32-bit words", "memory loops", "Clears a bounded sequence of 32-bit elements.", "Repeated stores write zero across the destination.", "Compilers may turn the loop into memset despite disabled builtins.", "Clearing memory is not automatically anti-forensic wiping."),
    _lesson("parse-u16-le", "Parse little-endian 16-bit data", "memory and parsing", "Combines two bytes into one little-endian 16-bit value.", "Byte loads, widening, shift, and OR form the result.", "Load order reveals serialized byte order.", "Host endianness and data endianness are separate."),
    _lesson("parse-u32-be", "Parse big-endian 32-bit data", "memory and parsing", "Combines four bytes into one big-endian 32-bit value.", "Four widened byte loads are shifted into distinct positions.", "Repeated shift-and-OR patterns indicate field parsing.", "Do not assume the host uses the same byte order."),
    _lesson("write-u32-le", "Write little-endian 32-bit data", "memory and parsing", "Serializes a 32-bit value into four little-endian bytes.", "Shifts and narrowing stores write successive bytes.", "Store order reveals output endianness.", "This may be serialization rather than obfuscation."),
    _lesson("stack-array", "Local stack array", "memory and parsing", "Builds and reduces a small volatile byte array on the stack.", "Stack-relative stores and loads access the local object.", "Repeated fixed frame offsets may represent a local array.", "A stack buffer is not necessarily unsafe without a violated bound."),
    _lesson("xor-buffer", "Transform a buffer with XOR", "reverse-engineering patterns", "XORs every byte with a key in place.", "The buffer and loop state change.", "Inspect producers and consumers of the transformed bytes.", "This is dual-use encoding, not automatically malware."),
    _lesson("checksum", "Compute a rolling checksum", "reverse-engineering patterns", "Combines every byte into a rolling 32-bit state.", "Shift/add/subtract operations update the accumulator.", "Identify constants and loop boundaries before naming an algorithm.", "Similar instruction shapes can represent hashes or ordinary indexing."),
    _lesson("xor-key-cycle", "XOR with a repeating key", "reverse-engineering patterns", "Transforms a buffer using a bounded repeating key.", "Two indexes, modulo, and XOR update each byte.", "Key-length modulo and repeated access are stronger clues than XOR alone.", "The operation is reversible but not necessarily encryption."),
    _lesson("additive-decode", "Subtract a byte key", "reverse-engineering patterns", "Subtracts one byte key from every buffer element in place.", "A byte load, subtraction, and store repeat across the buffer.", "Inspect where the key and transformed data originate.", "A simple transform may be formatting or encoding."),
    _lesson("rolling-hash", "FNV-style rolling hash", "reverse-engineering patterns", "Updates a 32-bit hash with every input byte and a fixed multiplier.", "XOR and multiplication feed loop-carried state.", "Constants plus operation order help identify a hash family.", "Confirm initialization and width before naming an exact variant."),
    _lesson("fibonacci", "Iterative state machine", "loops and arrays", "Updates two dependent state values across a counted loop.", "Multiple registers rotate through previous/current/next roles.", "Use data dependencies rather than register names to assign roles.", "Compiler register allocation can obscure source variables."),
    _lesson("factorial", "Multiplicative loop", "loops and arrays", "Multiplies a descending sequence of values.", "An accumulator grows while the loop variable decreases.", "A backward edge plus compare reveals the loop boundary.", "Overflow is possible even when the control flow is clear."),
    _lesson("switch-dispatch", "Switch dispatch", "high-level structures", "Selects one of several arithmetic operations.", "A bounds check and branches or a table route control.", "Look for jump tables, value tables, or comparison trees.", "A switch is not guaranteed to compile as an indirect jump."),
    _lesson("structure-fields", "Read structure fields", "high-level structures", "Reads fields at stable offsets from one base pointer.", "Several memory loads use related displacements.", "Collect every offset before defining a structure.", "One function may expose only part of the layout."),
    _lesson("structure-update", "Update structure fields", "high-level structures", "Mutates related fields in a shared record.", "Stores at stable offsets update values and flags.", "Grouped base-relative stores support a structure hypothesis.", "Field names and semantics still require evidence."),
    _lesson("linked-list-count", "Traverse a linked list", "high-level structures", "Follows next pointers until null and counts nodes.", "A pointer is repeatedly loaded from a stable field offset.", "Pointer chasing with a null exit is a linked-structure clue.", "The structure may be a tree path or chain rather than a list."),
    _lesson("indirect-call", "Call a function pointer", "calls and ABI", "Invokes a caller-supplied function pointer.", "Arguments are prepared, then control transfers indirectly.", "Trace the pointer through callbacks, tables, or imports.", "Indirect calls are common in legitimate software."),
    _lesson("callback-transform", "Apply a callback across an array", "calls and ABI", "Calls a supplied function pointer for every array element.", "Loop state survives repeated indirect calls and stores their results.", "Track volatile registers and saved loop variables across each call.", "A callback loop is common framework behavior."),
    _lesson("direct-call", "Direct helper call", "calls and ABI", "Calls a local non-inlined helper and returns its transformed result.", "Arguments enter ABI registers and CALL transfers to a fixed symbol.", "Direct call targets define natural interprocedural boundaries.", "The callee's name may be stripped in real samples."),
    _lesson("recursive-sum", "Recursive function", "calls and ABI", "Calls itself with a smaller argument until a base case.", "Each call creates ABI-visible input and return state.", "Identify the base case and recurrence separately.", "Optimizers may turn recursion into a loop."),
    _lesson("byte-swap", "Reverse byte order", "bit operations", "Reorders the four bytes of a 32-bit value.", "Masks and shifts, or a BSWAP instruction, produce the result.", "Recognize endian conversion idioms.", "Byte order is a representation issue, not encryption."),
    _lesson("dot-product", "Multiply and accumulate", "loops and arrays", "Multiplies paired array elements and accumulates a 64-bit sum.", "Two indexed reads, a multiply, and a wide accumulator repeat.", "Check operand extension before assigning signedness.", "Optimized builds may vectorize this shape."),
)


def catalog() -> tuple[Lesson, ...]:
    return _LESSONS


def get_lesson(lesson_id: str) -> Lesson | None:
    normalized = lesson_id.strip().lower()
    normalized = {
        "load-u32": "mov-load",
        "store-u32": "mov-store",
        "zero-extend": "movzx",
        "sign-extend": "movsx",
        "swap-values": "xchg",
    }.get(normalized, normalized)
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
