from .cfg import CFG, CFGBuilder, CFGSVGRenderer, CFGTextRenderer
from .disassembler import Disassembler, Function, Instruction
from .flirt import FlirtMatch, FlirtMatcher
from .pattern_detector import MalwarePattern, PatternDetector
from .static_analyzer import BinaryInfo, ImportInfo, SectionInfo, StaticAnalyzer

__all__ = [
    'StaticAnalyzer', 'BinaryInfo', 'SectionInfo', 'ImportInfo',
    'Disassembler', 'Function', 'Instruction',
    'AIAnalyzer', 'AIAnalysis', 'AIAnalyzerError', 'OfflineAnalyzer',
    'CFGBuilder', 'CFGTextRenderer', 'CFGSVGRenderer', 'CFG',
    'PatternDetector', 'MalwarePattern', 'FlirtMatcher', 'FlirtMatch',
]


def __getattr__(name):
    """Keep deterministic static analysis importable without the AI SDK."""
    if name in {'AIAnalyzer', 'AIAnalysis', 'AIAnalyzerError', 'OfflineAnalyzer'}:
        from . import ai_analyzer
        return getattr(ai_analyzer, name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
