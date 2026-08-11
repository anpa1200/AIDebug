import hashlib
import io
import logging
import math
import os
import re
import stat
from dataclasses import dataclass, field

import config

logger = logging.getLogger(__name__)

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    flags: list
    data: bytes = field(default=b'', repr=False)


@dataclass
class ImportInfo:
    dll: str
    functions: list


@dataclass
class BinaryInfo:
    path: str
    filename: str
    sha256: str
    file_format: str      # 'PE', 'ELF', or a derived format such as 'C/ELF'
    arch: str             # 'x86', 'x86-64', 'riscv64', etc.
    bits: int             # 32 or 64
    os_target: str        # 'Windows', 'Linux', etc.
    entry_point: int
    image_base: int
    sections: list
    imports: list
    exports: list
    strings: list
    all_string_data: dict  # address -> string
    raw_data: bytes = field(default=b'', repr=False)
    function_symbols: list = field(default_factory=list)
    analysis_origin: str = 'binary'
    compiled_sha256: str | None = None

    @property
    def text_section(self) -> SectionInfo | None:
        for s in self.sections:
            if 'EXECUTE' in s.flags and s.data:
                return s
        return None

    @property
    def imports_flat(self) -> list:
        """All imported function names as a flat list."""
        funcs = []
        for imp in self.imports:
            funcs.extend(imp.functions)
        return funcs


class StaticAnalyzer:

    MIN_STRING_LEN = config.MIN_STRING_LENGTH

    def analyze(self, path: str) -> BinaryInfo:
        try:
            path_stat = os.stat(path)
        except OSError as exc:
            raise ValueError(f"Unable to inspect binary path: {exc}") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise ValueError("Binary path must point to a regular file")
        if path_stat.st_size > config.MAX_BINARY_SIZE_BYTES:
            raise ValueError(
                f"Binary is too large ({path_stat.st_size} bytes); "
                f"maximum is {config.MAX_BINARY_SIZE_BYTES} bytes"
            )

        open_flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0)
        try:
            descriptor = os.open(path, open_flags)
        except OSError as exc:
            raise ValueError(f"Unable to open binary path: {exc}") from exc
        with os.fdopen(descriptor, 'rb') as f:
            # Re-check the opened descriptor so a path swap between stat() and
            # open() cannot make us read a device, FIFO, or oversized file.
            opened_stat = os.fstat(f.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError("Binary path must point to a regular file")
            if opened_stat.st_size > config.MAX_BINARY_SIZE_BYTES:
                raise ValueError(
                    f"Binary is too large ({opened_stat.st_size} bytes); "
                    f"maximum is {config.MAX_BINARY_SIZE_BYTES} bytes"
                )
            raw_data = f.read(config.MAX_BINARY_SIZE_BYTES + 1)

        if len(raw_data) > config.MAX_BINARY_SIZE_BYTES:
            raise ValueError(
                f"Binary exceeds the {config.MAX_BINARY_SIZE_BYTES}-byte analysis limit"
            )

        sha256 = hashlib.sha256(raw_data).hexdigest()
        filename = os.path.basename(path)

        if raw_data[:2] == b'MZ':
            info = self._analyze_pe(path, raw_data, sha256, filename)
        elif raw_data[:4] == b'\x7fELF':
            info = self._analyze_elf(path, raw_data, sha256, filename)
        else:
            from .file_type import FileTypeDetector

            detected = FileTypeDetector().identify_bytes(raw_data, filename=filename)
            if detected.is_unknown:
                raise ValueError(
                    f"Unknown binary format: {raw_data[:4].hex()}; use --identify for "
                    "broad file-type detection and optional AI fallback"
                )
            raise ValueError(
                f"Detected {detected.type_name} ({detected.mime_type}), which is not a "
                "supported executable analysis format; use --identify for classification"
            )

        info.raw_data = raw_data
        return info

    # ------------------------------------------------------------------
    # PE analysis
    # ------------------------------------------------------------------

    def _analyze_pe(self, path, raw_data, sha256, filename) -> BinaryInfo:
        if not HAS_PEFILE:
            raise ImportError("pefile not installed — run: pip install pefile")

        # Parse the exact bytes that were hashed above. Reopening ``path`` here
        # would allow a replaced file to produce internally inconsistent data.
        pe = pefile.PE(data=raw_data, fast_load=False)

        machine = pe.FILE_HEADER.Machine
        arch_map = {
            0x014c: ('x86', 32),
            0x8664: ('x86-64', 64),
            0x01c4: ('arm', 32),
            0xaa64: ('aarch64', 64),
        }
        arch, bits = arch_map.get(machine, (f'unknown({hex(machine)})', 32))

        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint + image_base

        # Sections
        sections = []
        for sec in pe.sections:
            name = sec.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
            data = sec.get_data()
            entropy = self._entropy(data)
            flags = []
            ch = sec.Characteristics
            if ch & 0x20000000:
                flags.append('EXECUTE')
            if ch & 0x40000000:
                flags.append('READ')
            if ch & 0x80000000:
                flags.append('WRITE')
            sections.append(SectionInfo(
                name=name,
                virtual_address=sec.VirtualAddress + image_base,
                virtual_size=sec.Misc_VirtualSize,
                raw_size=sec.SizeOfRawData,
                entropy=entropy,
                flags=flags,
                data=data,
            ))

        # Imports
        imports = []
        import_count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='replace')
                funcs = []
                for imp in entry.imports:
                    if import_count >= config.MAX_IMPORT_FUNCTIONS:
                        break
                    if imp.name:
                        funcs.append(imp.name.decode('utf-8', errors='replace'))
                    else:
                        funcs.append(f'ordinal_{imp.ordinal}')
                    import_count += 1
                if funcs:
                    imports.append(ImportInfo(dll=dll, functions=funcs))
                if import_count >= config.MAX_IMPORT_FUNCTIONS:
                    break

        # Exports
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:config.MAX_EXPORTS]:
                name = exp.name.decode('utf-8', errors='replace') if exp.name else f'ord_{exp.ordinal}'
                exports.append({
                    'name': name,
                    'address': exp.address + image_base,
                    'ordinal': exp.ordinal,
                })

        strings, string_data = self._extract_strings(raw_data, image_base, pe)
        pe.close()

        return BinaryInfo(
            path=path,
            filename=filename,
            sha256=sha256,
            file_format='PE',
            arch=arch,
            bits=bits,
            os_target='Windows',
            entry_point=entry_point,
            image_base=image_base,
            sections=sections,
            imports=imports,
            exports=exports,
            strings=strings,
            all_string_data=string_data,
        )

    # ------------------------------------------------------------------
    # ELF analysis
    # ------------------------------------------------------------------

    def _analyze_elf(self, path, raw_data, sha256, filename) -> BinaryInfo:
        if not HAS_ELFTOOLS:
            raise ImportError("pyelftools not installed — run: pip install pyelftools")

        # As with PE parsing, operate on the exact bytes that were hashed.
        with io.BytesIO(raw_data) as f:
            elf = ELFFile(f)

            arch_map = {
                'x86':     ('x86', 32),
                'x64':     ('x86-64', 64),
                'ARM':     ('arm', 32),
                'AArch64': ('aarch64', 64),
                'RISC-V':  ('riscv64' if elf.elfclass == 64 else 'riscv32', elf.elfclass),
                'MIPS':    ('mips', 32),
            }
            arch_name = elf.get_machine_arch()
            arch, bits = arch_map.get(arch_name, (arch_name, elf.elfclass))

            entry_point = elf.header.e_entry
            load_segments = []
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    load_segments.append((
                        int(segment['p_offset']),
                        int(segment['p_filesz']),
                        int(segment['p_vaddr']),
                    ))
            image_base = min((segment[2] for segment in load_segments), default=0)

            sections = []
            for sec in elf.iter_sections():
                if sec.name and sec.data_size > 0:
                    offset = int(sec['sh_offset'])
                    raw_size = int(sec['sh_size'])
                    # Do not materialize SHT_NOBITS or transparently decompress
                    # attacker-controlled section sizes. Executable bytes are
                    # read directly from the already size-bounded sample.
                    if sec['sh_type'] == 'SHT_NOBITS' or offset >= len(raw_data):
                        data = b''
                    else:
                        data = raw_data[offset:min(offset + raw_size, len(raw_data))]
                    entropy = self._entropy(data)
                    sh_flags = sec['sh_flags']
                    flags = []
                    if sh_flags & 0x2:
                        flags.append('READ')
                    if sh_flags & 0x4:
                        flags.append('EXECUTE')
                    if sh_flags & 0x1:
                        flags.append('WRITE')
                    sections.append(SectionInfo(
                        name=sec.name,
                        virtual_address=sec['sh_addr'],
                        virtual_size=sec.data_size,
                        raw_size=sec.data_size,
                        entropy=entropy,
                        flags=flags,
                        data=data,
                    ))

            export_candidates = set()
            function_symbol_candidates = set()
            undefined_dynamic_symbols = set()
            executable_ranges = [
                (section.virtual_address, section.virtual_address + section.virtual_size)
                for section in sections if 'EXECUTE' in section.flags
            ]
            scanned_symbols = 0
            for sec in elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if scanned_symbols >= config.MAX_SYMBOLS_TO_SCAN:
                            break
                        scanned_symbols += 1
                        address = int(sym['st_value'])
                        symbol_type = sym['st_info']['type']
                        binding = sym['st_info']['bind']
                        if (
                            sec.name == '.dynsym'
                            and sym.name
                            and sym['st_shndx'] == 'SHN_UNDEF'
                            and symbol_type in {'STT_FUNC', 'STT_NOTYPE'}
                            and binding in {'STB_GLOBAL', 'STB_WEAK'}
                            and len(undefined_dynamic_symbols) < config.MAX_IMPORT_FUNCTIONS
                        ):
                            undefined_dynamic_symbols.add(sym.name)
                        in_exec = any(start <= address < end for start, end in executable_ranges)
                        if sym.name and address > 0 and in_exec and symbol_type == 'STT_FUNC':
                            if len(function_symbol_candidates) < config.MAX_FUNCTION_SYMBOLS:
                                function_symbol_candidates.add(
                                    (address, sym.name, int(sym['st_size']))
                                )
                            if (
                                binding in {'STB_GLOBAL', 'STB_WEAK'}
                                and len(export_candidates) < config.MAX_EXPORTS
                            ):
                                export_candidates.add((address, sym.name))
                    if scanned_symbols >= config.MAX_SYMBOLS_TO_SCAN:
                        break

            exports = [
                {'name': name, 'address': address, 'ordinal': 0}
                for address, name in sorted(export_candidates)
            ]
            function_symbols = [
                {'name': name, 'address': address, 'size': size}
                for address, name, size in sorted(function_symbol_candidates)
            ]
            imports = []
            if undefined_dynamic_symbols:
                imports.append(ImportInfo(
                    dll='ELF dynamic symbols',
                    functions=sorted(undefined_dynamic_symbols),
                ))

        def elf_offset_to_va(offset: int) -> int:
            for file_offset, file_size, virtual_address in load_segments:
                if file_offset <= offset < file_offset + file_size:
                    return virtual_address + (offset - file_offset)
            return offset

        strings, string_data = self._extract_strings(
            raw_data, image_base, None, offset_mapper=elf_offset_to_va
        )

        return BinaryInfo(
            path=path,
            filename=filename,
            sha256=sha256,
            file_format='ELF',
            arch=arch,
            bits=bits,
            os_target='Linux',
            entry_point=entry_point,
            image_base=image_base,
            sections=sections,
            imports=imports,
            exports=exports,
            strings=strings,
            all_string_data=string_data,
            function_symbols=function_symbols,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_strings(self, data: bytes, image_base: int, pe, offset_mapper=None) -> tuple:
        strings = []
        string_data = {}
        seen = set()

        def record(offset: int, value: str) -> bool:
            if len(string_data) >= config.MAX_EXTRACTED_STRINGS:
                return False
            addr = (
                offset_mapper(offset)
                if offset_mapper is not None
                else self._raw_offset_to_va(offset, image_base, pe)
            )
            string_data[addr] = value
            if value not in seen:
                seen.add(value)
                strings.append(value)
            return True

        # ASCII strings
        ascii_pattern = (
            rb'[ -~]{' + str(self.MIN_STRING_LEN).encode() + rb','
            + str(config.MAX_STRING_CHARS).encode() + rb'}'
        )
        for match in re.finditer(ascii_pattern, data):
            raw = match.group()
            s = raw.decode('ascii', errors='replace')
            if not record(match.start(), s):
                break

        # Wide strings (UTF-16 LE)
        if len(string_data) < config.MAX_EXTRACTED_STRINGS:
            for match in re.finditer(
                rb'(?:[ -~]\x00){' + str(self.MIN_STRING_LEN).encode() + rb','
                + str(config.MAX_STRING_CHARS).encode() + rb'}', data
            ):
                raw = match.group()
                s = raw.decode('utf-16-le', errors='replace').rstrip('\x00')
                if len(s) >= self.MIN_STRING_LEN:
                    if not record(match.start(), f'[W] {s}'):
                        break

        return strings, string_data

    def _raw_offset_to_va(self, offset: int, image_base: int, pe) -> int:
        if pe is None:
            return offset
        try:
            rva = pe.get_rva_from_offset(offset)
            if rva is not None:
                return rva + image_base
        except Exception as exc:
            logger.debug('Unable to map PE raw offset %#x to an RVA: %s', offset, exc)
        return offset

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        ent = 0.0
        for f in freq:
            if f > 0:
                p = f / n
                ent -= p * math.log2(p)
        return round(ent, 2)
