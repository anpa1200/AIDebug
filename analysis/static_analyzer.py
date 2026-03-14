import os
import re
import math
import hashlib
from dataclasses import dataclass, field
from typing import Optional

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
    file_format: str      # 'PE' or 'ELF'
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

    @property
    def text_section(self) -> Optional[SectionInfo]:
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

    MIN_STRING_LEN = 5

    def analyze(self, path: str) -> BinaryInfo:
        with open(path, 'rb') as f:
            raw_data = f.read()

        sha256 = hashlib.sha256(raw_data).hexdigest()
        filename = os.path.basename(path)

        if raw_data[:2] == b'MZ':
            info = self._analyze_pe(path, raw_data, sha256, filename)
        elif raw_data[:4] == b'\x7fELF':
            info = self._analyze_elf(path, raw_data, sha256, filename)
        else:
            raise ValueError(f"Unknown binary format: {raw_data[:4].hex()}")

        info.raw_data = raw_data
        return info

    # ------------------------------------------------------------------
    # PE analysis
    # ------------------------------------------------------------------

    def _analyze_pe(self, path, raw_data, sha256, filename) -> BinaryInfo:
        if not HAS_PEFILE:
            raise ImportError("pefile not installed — run: pip install pefile")

        pe = pefile.PE(path)

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
            if ch & 0x20000000: flags.append('EXECUTE')
            if ch & 0x40000000: flags.append('READ')
            if ch & 0x80000000: flags.append('WRITE')
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
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='replace')
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode('utf-8', errors='replace'))
                    else:
                        funcs.append(f'ordinal_{imp.ordinal}')
                imports.append(ImportInfo(dll=dll, functions=funcs))

        # Exports
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
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

        with open(path, 'rb') as f:
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
            image_base = 0

            sections = []
            for sec in elf.iter_sections():
                if sec.name and sec.data_size > 0:
                    data = sec.data()
                    entropy = self._entropy(data)
                    sh_flags = sec['sh_flags']
                    flags = ['READ']
                    if sh_flags & 0x4: flags.append('EXECUTE')
                    if sh_flags & 0x2: flags.append('WRITE')
                    sections.append(SectionInfo(
                        name=sec.name,
                        virtual_address=sec['sh_addr'],
                        virtual_size=sec.data_size,
                        raw_size=sec.data_size,
                        entropy=entropy,
                        flags=flags,
                        data=data,
                    ))

            exports = []
            for sec in elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if sym.name and sym['st_value'] > 0:
                            exports.append({
                                'name': sym.name,
                                'address': sym['st_value'],
                                'ordinal': 0,
                            })

        strings, string_data = self._extract_strings(raw_data, 0, None)

        return BinaryInfo(
            path=path,
            filename=filename,
            sha256=sha256,
            file_format='ELF',
            arch=arch,
            bits=bits,
            os_target='Linux',
            entry_point=entry_point,
            image_base=0,
            sections=sections,
            imports=[],
            exports=exports,
            strings=strings,
            all_string_data=string_data,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_strings(self, data: bytes, image_base: int, pe) -> tuple:
        strings = []
        string_data = {}

        # ASCII strings
        for match in re.finditer(rb'[ -~]{' + str(self.MIN_STRING_LEN).encode() + rb',}', data):
            s = match.group().decode('ascii', errors='replace')
            offset = match.start()
            addr = self._raw_offset_to_va(offset, image_base, pe)
            strings.append(s)
            string_data[addr] = s

        # Wide strings (UTF-16 LE)
        for match in re.finditer(rb'(?:[ -~]\x00){' + str(self.MIN_STRING_LEN).encode() + rb',}', data):
            try:
                s = match.group().decode('utf-16-le', errors='replace').rstrip('\x00')
                if len(s) >= self.MIN_STRING_LEN:
                    strings.append(f'[W] {s}')
                    string_data[match.start()] = f'[W] {s}'
            except Exception:
                pass

        # Deduplicate
        seen, unique = set(), []
        for s in strings:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique, string_data

    def _raw_offset_to_va(self, offset: int, image_base: int, pe) -> int:
        if pe is None:
            return offset
        try:
            rva = pe.get_rva_from_offset(offset)
            if rva:
                return rva + image_base
        except Exception:
            pass
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
