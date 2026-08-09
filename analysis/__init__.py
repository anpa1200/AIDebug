from .cfg import CFG, CFGBuilder, CFGSVGRenderer, CFGTextRenderer
from .decompiler import (
    DecompiledFunction,
    DecompilerError,
    GhidraDecompiler,
    render_full_decompilation,
    write_full_decompilation,
)
from .disassembler import Disassembler, Function, Instruction
from .flirt import FlirtMatch, FlirtMatcher
from .pattern_detector import MalwarePattern, PatternDetector
from .pe_structure import (
    PEASLRAssessment,
    PEBaseRelocationBlock,
    PEBaseRelocationEntry,
    PEDataDirectory,
    PEDelayImportDescriptorRecord,
    PEExportRecord,
    PEHeader,
    PEHeaderField,
    PEImportDescriptorRecord,
    PEImportRecord,
    PEResourceDataRecord,
    PEResourceDirectoryRecord,
    PESectionRecord,
    PEStructure,
    PEStructureAnalyzer,
    render_hex_page,
)
from .source_analyzer import CSourceAnalyzer
from .static_analyzer import BinaryInfo, ImportInfo, SectionInfo, StaticAnalyzer

__all__ = [
    'StaticAnalyzer', 'CSourceAnalyzer', 'BinaryInfo', 'SectionInfo', 'ImportInfo',
    'Disassembler', 'Function', 'Instruction',
    'GhidraDecompiler', 'DecompiledFunction', 'DecompilerError',
    'render_full_decompilation', 'write_full_decompilation',
    'AIAnalyzer', 'AIAnalysis', 'AIAnalyzerError', 'OfflineAnalyzer',
    'CFGBuilder', 'CFGTextRenderer', 'CFGSVGRenderer', 'CFG',
    'PatternDetector', 'MalwarePattern', 'FlirtMatcher', 'FlirtMatch',
    'PEStructureAnalyzer', 'PEStructure', 'PEHeader', 'PEHeaderField',
    'PEDataDirectory', 'PESectionRecord', 'PEImportDescriptorRecord',
    'PEDelayImportDescriptorRecord',
    'PEResourceDirectoryRecord', 'PEResourceDataRecord',
    'PEBaseRelocationBlock', 'PEBaseRelocationEntry', 'PEASLRAssessment',
    'PEImportRecord', 'PEExportRecord',
    'render_hex_page',
]


def __getattr__(name):
    """Keep deterministic static analysis importable without the AI SDK."""
    if name in {'AIAnalyzer', 'AIAnalysis', 'AIAnalyzerError', 'OfflineAnalyzer'}:
        from . import ai_analyzer
        return getattr(ai_analyzer, name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
