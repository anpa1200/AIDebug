import os

# --- Claude API ---
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
AI_MODEL = os.environ.get("AIDEBUG_AI_MODEL", "").strip() or "claude-opus-4-8"
AI_PROMPT_SCHEMA_VERSION = 4
AI_CACHE_KEY = f"{AI_MODEL}:prompt-v{AI_PROMPT_SCHEMA_VERSION}"
AI_MAX_TOKENS = 3072
AI_TIMEOUT_SECONDS = 90.0
MAX_AI_RESPONSE_CHARS = 50_000
MAX_AI_FOLLOWUP_CHARS = 4_000
MAX_AI_FOLLOWUP_TURNS = 6

# --- Sample paths ---
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

# --- Database ---
_state_home = os.environ.get("XDG_STATE_HOME")
if not _state_home:
    if os.name == "nt":
        _state_home = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    else:
        _state_home = os.path.join(os.path.expanduser("~"), ".local", "state")
_db_override = os.environ.get("AIDEBUG_DB_PATH", "").strip()
DB_PATH = os.path.abspath(os.path.expanduser(
    _db_override or os.path.join(_state_home, "aidebug", "traces.db")
))

# --- Analysis limits ---
MAX_BINARY_SIZE_BYTES = 128 * 1024 * 1024
MAX_C_SOURCE_SIZE_BYTES = 2 * 1024 * 1024
C_SOURCE_COMPILE_TIMEOUT_SECONDS = 30.0
MAX_EXTRACTED_STRINGS = 100_000
MAX_STRING_CHARS = 4_096
MAX_SYMBOLS_TO_SCAN = 100_000
MAX_IMPORT_FUNCTIONS = 50_000
MAX_EXPORTS = 50_000
MAX_FUNCTION_SYMBOLS = 50_000
MAX_FUNCTIONS_TO_DISCOVER = 300
MAX_INSTRUCTIONS_PER_FUNCTION = 250
MAX_DISASSEMBLY_CHARS = 3500      # chars sent to AI
MAX_DECOMPILED_CHARS = 12_000
MAX_AI_DECOMPILED_CHARS = 4_000
MAX_FULL_DECOMPILATION_FUNCTIONS = MAX_FUNCTIONS_TO_DISCOVER
GHIDRA_DECOMPILE_TIMEOUT_SECONDS = 300.0
GHIDRA_FUNCTION_TIMEOUT_SECONDS = 30
MAX_STRINGS_PER_FUNCTION = 15
MIN_STRING_LENGTH = 5
MAX_RUNTIME_EVENTS = 10_000
MAX_ACTIVE_INVOCATIONS = 2_048
MAX_PERSISTED_EVENTS_PER_TYPE = 10_000
MAX_DYNAMIC_FUNCTION_HOOKS = 50
INSTRUMENTATION_READY_TIMEOUT_SECONDS = 3.0

# --- UI ---
APP_TITLE = "AIDebug — AI-Assisted Malware Analyzer"
APP_VERSION = "1.3.3"
