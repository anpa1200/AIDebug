import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit

try:
    from dotenv import load_dotenv
except ImportError:  # Existing offline installations remain importable.
    load_dotenv = None


def _load_aidebug_env() -> None:
    """Load only an explicitly trusted AIDebug env file, never an arbitrary CWD file."""
    configured = os.environ.get("AIDEBUG_ENV_FILE", "").strip()
    env_path = Path(configured).expanduser() if configured else Path(__file__).with_name(".env")
    if load_dotenv is not None and env_path.is_file():
        load_dotenv(env_path, override=False)


_load_aidebug_env()

# --- LLM providers ---
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
GEMINI_API_KEY = (
    os.environ.get("GEMINI_API_KEY", "").strip()
    or os.environ.get("GOOGLE_API_KEY", "").strip()
)
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "").strip()
LLM_PROVIDER = os.environ.get("AIDEBUG_LLM_PROVIDER", "auto").strip().lower() or "auto"

LLM_DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-8",
    "openai": "gpt-5.6-terra",
    "gemini": "gemini-3.6-flash",
    "ollama": "qwen3:8b",
}
LLM_BASE_URLS = {
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
    "ollama": "http://127.0.0.1:11434/v1",
}


def is_local_llm_endpoint(provider: str, base_url: str) -> bool:
    """Return true only for supported, literal loopback Ollama HTTP(S) URLs."""
    if str(provider).strip().lower() != "ollama":
        return False
    try:
        parsed = urlsplit(str(base_url).strip())
    except (TypeError, ValueError):
        return False
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    hostname = parsed.hostname.rstrip(".").casefold()
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_ollama_base_url(base_url: str) -> str:
    """Validate the OpenAI-compatible Ollama transport supported by AIDebug."""
    normalized = str(base_url).strip()
    try:
        parsed = urlsplit(normalized)
    except (TypeError, ValueError) as exc:
        raise ValueError("OLLAMA_BASE_URL must be a valid HTTP(S) URL") from exc
    if parsed.scheme.lower() in {"unix", "http+unix"}:
        raise ValueError(
            "Unix-socket Ollama URLs are not supported; use an HTTP(S) loopback endpoint"
        )
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("OLLAMA_BASE_URL must be a valid HTTP(S) URL")
    return normalized


def _configured_providers() -> list[str]:
    providers = []
    if ANTHROPIC_API_KEY:
        providers.append("anthropic")
    if OPENAI_API_KEY:
        providers.append("openai")
    if GEMINI_API_KEY:
        providers.append("gemini")
    if OLLAMA_BASE_URL:
        providers.append("ollama")
    return providers


def resolve_llm_settings() -> dict | None:
    """Resolve one configured provider without silently choosing between multiple keys."""
    valid = set(LLM_DEFAULT_MODELS)
    if LLM_PROVIDER not in valid | {"auto"}:
        raise ValueError(
            "AIDEBUG_LLM_PROVIDER must be one of: auto, anthropic, openai, gemini, ollama"
        )

    configured = _configured_providers()
    if LLM_PROVIDER == "auto":
        if not configured:
            return None
        if len(configured) > 1:
            raise ValueError(
                "Multiple LLM providers are configured; set AIDEBUG_LLM_PROVIDER explicitly"
            )
        provider = configured[0]
    else:
        provider = LLM_PROVIDER

    key_names = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "ollama": None,
    }
    api_keys = {
        "anthropic": ANTHROPIC_API_KEY,
        "openai": OPENAI_API_KEY,
        "gemini": GEMINI_API_KEY,
        "ollama": "ollama",
    }
    key_name = key_names[provider]
    if key_name and not api_keys[provider]:
        raise ValueError(f"{key_name} is not set for provider {provider!r}")

    model = (
        os.environ.get("AIDEBUG_AI_MODEL", "").strip()
        or os.environ.get(f"AIDEBUG_{provider.upper()}_MODEL", "").strip()
        or LLM_DEFAULT_MODELS[provider]
    )
    base_url = os.environ.get("AIDEBUG_LLM_BASE_URL", "").strip()
    if not base_url:
        base_url = OLLAMA_BASE_URL if provider == "ollama" else LLM_BASE_URLS.get(provider, "")
    if provider == "ollama" and not base_url:
        base_url = LLM_BASE_URLS["ollama"]
    if provider == "ollama":
        base_url = validate_ollama_base_url(base_url)

    return {
        "provider": provider,
        "model": model,
        "api_key": api_keys[provider],
        "key_name": key_name,
        "base_url": base_url,
        "is_local": is_local_llm_endpoint(provider, base_url),
    }


try:
    _INITIAL_LLM_SETTINGS = resolve_llm_settings()
except ValueError:
    _INITIAL_LLM_SETTINGS = None
AI_PROVIDER = (_INITIAL_LLM_SETTINGS or {}).get("provider", "anthropic")
AI_MODEL = (
    (_INITIAL_LLM_SETTINGS or {}).get("model")
    or os.environ.get("AIDEBUG_AI_MODEL", "").strip()
    or LLM_DEFAULT_MODELS[AI_PROVIDER]
)
AI_PROMPT_SCHEMA_VERSION = 5
AI_CACHE_KEY = f"{AI_PROVIDER}:{AI_MODEL}:prompt-v{AI_PROMPT_SCHEMA_VERSION}"
AI_MAX_TOKENS = 3072
AI_STRING_CHUNK_MAX_ITEMS = 40
AI_STRING_CHUNK_MAX_CHARS = 48_000
AI_STRING_MAX_CHUNKS = 25_000
AI_STRING_MAX_CONSECUTIVE_FAILURES = 3
AI_STRING_MAX_TOKENS = 8_192
AI_STRING_REDUCE_MAX_CHARS = 120_000
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
MAX_EXTRACTED_STRINGS = 25_000
MAX_STRING_CHARS = 4_096
MAX_SYMBOLS_TO_SCAN = 100_000
MAX_IMPORT_FUNCTIONS = 50_000
MAX_IMPORT_DESCRIPTORS = 4_096
MAX_DELAY_IMPORT_DESCRIPTORS = 4_096
MAX_RESOURCE_RECORDS = 50_000
MAX_RESOURCE_DEPTH = 8
MAX_RESOURCE_PREVIEW_BYTES = 64
MAX_RICH_HEADER_ENTRIES = 4_096
MAX_DEBUG_DIRECTORY_ENTRIES = 4_096
MAX_DEBUG_DATA_PREVIEW_BYTES = 64
MAX_PDB_PATH_BYTES = 4_096
MAX_OVERLAY_PREVIEW_BYTES = 64
MAX_DOTNET_METADATA_STREAMS = 64
MAX_DOTNET_STREAM_NAME_BYTES = 128
MAX_DOTNET_VERSION_BYTES = 4_096
MAX_DOTNET_STRING_BYTES = 4_096
MAX_DOTNET_ASSEMBLY_REFERENCES = 10_000
MAX_DOTNET_PREVIEW_BYTES = 64
MAX_BASE_RELOCATION_BLOCKS = 50_000
MAX_BASE_RELOCATION_ENTRIES = 500_000
MAX_TLS_CALLBACKS = 4_096
MAX_TLS_PREVIEW_BYTES = 64
MAX_RUNTIME_FUNCTIONS = 100_000
MAX_CFG_FUNCTIONS = 500_000
MAX_WIN_CERTIFICATE_ENTRIES = 256
MAX_PKCS7_CERTIFICATES = 512
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
APP_VERSION = "3.1.0"
