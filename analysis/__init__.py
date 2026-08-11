from .cfg import CFG, CFGBuilder, CFGSVGRenderer, CFGTextRenderer
from .decompiler import (
    DecompiledFunction,
    DecompilerError,
    GhidraDecompiler,
    render_full_decompilation,
    write_full_decompilation,
)
from .disassembler import Disassembler, Function, Instruction
from .file_type import FileTypeDetector, FileTypeResult
from .flirt import FlirtMatch, FlirtMatcher
from .pattern_detector import MalwarePattern, PatternDetector
from .pe_structure import (
    PEASLRAssessment,
    PEAuthenticode,
    PEAuthenticodeSigner,
    PEBaseRelocationBlock,
    PEBaseRelocationEntry,
    PECFGEvidence,
    PECFGTarget,
    PEDataDirectory,
    PEDebugDirectory,
    PEDebugRecord,
    PEDelayImportDescriptorRecord,
    PEDotNetAssemblyIdentity,
    PEDotNetAssemblyReference,
    PEDotNetHeader,
    PEDotNetStream,
    PEDotNetTable,
    PEEmbeddedCertificate,
    PEExceptionDirectory,
    PEExportRecord,
    PEHeader,
    PEHeaderField,
    PEImportDescriptorRecord,
    PEImportRecord,
    PELoadConfigField,
    PELoadConfiguration,
    PEMitigationFinding,
    PEOverlay,
    PEResourceDataRecord,
    PEResourceDirectoryRecord,
    PERichEntry,
    PERichHeader,
    PERuntimeFunction,
    PESectionRecord,
    PEStructure,
    PEStructureAnalyzer,
    PETLSCallback,
    PETLSDirectory,
    PEUnwindCode,
    PEUnwindInfo,
    PEWinCertificate,
    render_hex_page,
)
from .source_analyzer import CSourceAnalyzer
from .static_analyzer import BinaryInfo, ImportInfo, SectionInfo, StaticAnalyzer
from .string_analyzer import (
    SmartStringAnalysis,
    SmartStringAnalyzer,
    StringAnalyzer,
    StringRecord,
)

__all__ = [
    'StaticAnalyzer', 'CSourceAnalyzer', 'BinaryInfo', 'SectionInfo', 'ImportInfo',
    'StringAnalyzer', 'SmartStringAnalyzer', 'SmartStringAnalysis', 'StringRecord',
    'FileTypeDetector', 'FileTypeResult',
    'Disassembler', 'Function', 'Instruction',
    'GhidraDecompiler', 'DecompiledFunction', 'DecompilerError',
    'render_full_decompilation', 'write_full_decompilation',
    'AIAnalyzer', 'AIAnalysis', 'StringAIReport', 'AIAnalyzerError', 'OfflineAnalyzer',
    'CFGBuilder', 'CFGTextRenderer', 'CFGSVGRenderer', 'CFG',
    'PatternDetector', 'MalwarePattern', 'FlirtMatcher', 'FlirtMatch',
    'PEStructureAnalyzer', 'PEStructure', 'PEHeader', 'PEHeaderField',
    'PEDataDirectory', 'PESectionRecord', 'PEImportDescriptorRecord',
    'PEDebugDirectory', 'PEDebugRecord', 'PERichHeader', 'PERichEntry',
    'PEOverlay',
    'PEDotNetHeader', 'PEDotNetStream', 'PEDotNetTable',
    'PEDotNetAssemblyIdentity', 'PEDotNetAssemblyReference',
    'PEAuthenticode', 'PEWinCertificate', 'PEAuthenticodeSigner',
    'PEEmbeddedCertificate',
    'PEDelayImportDescriptorRecord',
    'PEResourceDirectoryRecord', 'PEResourceDataRecord',
    'PEBaseRelocationBlock', 'PEBaseRelocationEntry', 'PEASLRAssessment',
    'PECFGEvidence', 'PECFGTarget',
    'PETLSDirectory', 'PETLSCallback',
    'PEExceptionDirectory', 'PERuntimeFunction', 'PEUnwindInfo', 'PEUnwindCode',
    'PELoadConfiguration', 'PELoadConfigField', 'PEMitigationFinding',
    'PEImportRecord', 'PEExportRecord',
    'render_hex_page',
]


def __getattr__(name):
    """Keep deterministic static analysis importable without the AI SDK."""
    if name in {
        'AIAnalyzer', 'AIAnalysis', 'StringAIReport', 'AIAnalyzerError', 'OfflineAnalyzer'
    }:
        from . import ai_analyzer
        return getattr(ai_analyzer, name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
