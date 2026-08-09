# AIDebug real learning cases

This directory is the source corpus used by AIDebug Learning Mode. Each lesson
has its own minimal C file and exactly one public `learn_*` function. AIDebug
copies only the selected file and `case_common.h` to a temporary directory,
compiles it as an x86-64 ELF object, and analyzes the resulting machine code.
The temporary artifact is never executed.

It is also a complete external collection named **AIDebug Core 100**. The
schema-versioned `collection.json` lists exactly 100 case IDs in display order.
Load this directory through the same public interface available to custom
collections:

```bash
aidebug --learn --learning-collection ./learning/cases
```

For example:

```bash
aidebug --learn mov-load
aidebug --learn lea-arithmetic
aidebug --learn movsxd
aidebug --learn xchg
aidebug --learn test-bit
aidebug --learn binary-search
```

Each result shows three views of the same selected case:

1. the complete real C source from this directory;
2. the real instructions emitted by the local compiler;
3. pseudo-code independently recovered from the ELF by Ghidra.

The cases use the x86-64 System V ABI because they are compiled to Linux ELF.
The first integer or pointer arguments therefore normally arrive in `RDI`,
`RSI`, `RDX`, `RCX`, `R8`, and `R9`, rather than the Windows x64 order. Exact
instruction selection can vary with the compiler version, but dedicated cases
are tested to contain the instruction family named by the lesson.

`case_common.h` contains only the fixed-width type definitions and attributes
shared by the cases. It does not contain hidden implementations.

For a custom collection, copy `case_common.h`, add standalone files named with
lowercase IDs (for example `parse-header.c`), and expose a matching function
(`learn_parse_header`). Without a manifest, AIDebug discovers `*.c` files in
lexicographic order and supplies generic metadata. A `collection.json` can list
ID strings or metadata objects containing `id`, optional `source`, `title`,
`category`, `explanation`, `effects`, `analyst_clue`, and `pitfall` fields.

External source is compiled but never executed. Because the compiler still
parses it, only load source collections you have reviewed and trust.
