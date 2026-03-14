import os

# --- Claude API ---
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
AI_MODEL = "claude-opus-4-6"
AI_MAX_TOKENS = 2048

# --- Sample paths ---
SAMPLES_DIR = "/home/andrey/git_project/String-Analyzer/malware_samples"

# --- Database ---
DB_PATH = os.path.join(os.path.dirname(__file__), "traces.db")

# --- Analysis limits ---
MAX_FUNCTIONS_TO_DISCOVER = 300
MAX_INSTRUCTIONS_PER_FUNCTION = 250
MAX_DISASSEMBLY_CHARS = 3500      # chars sent to AI
MAX_STRINGS_PER_FUNCTION = 15
MIN_STRING_LENGTH = 5

# --- UI ---
APP_TITLE = "AIDebug — AI-Assisted Malware Analyzer"
APP_VERSION = "1.0"
