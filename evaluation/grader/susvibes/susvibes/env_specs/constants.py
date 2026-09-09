from enum import Enum

class TestItemStatus(Enum):
    FAILED = "FAILED"
    PASSED = "PASSED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    XFAIL = "XFAIL"
    
class TestStatus(Enum):
    STARTUP_ERROR = "startup_error"
    TIMEOUT = "timeout"
    COMPLETION = "completion"
    
FAILURE_STATUSES = {TestItemStatus.FAILED, TestItemStatus.ERROR}

TEST_SYMBOL_RESOLUTION_ERROR_PATTERNS = [
    r"ImportError: cannot import",
    r"AttributeError:.*?attribute", 
    r"NameError: name",
    r"UnboundLocalError:",
    r"TypeError:",
    r"pydantic\..*?ValidationError:",
    r"Unknown keyword argument"
]

DOCKERFILE_PATTERN = (
    r'^(FROM(?:[^\r\n]*\\\r?\n)*[^\r\n]*\r?\n)'
    r'(.*?)'
    r'^(COPY(?:[^\r\n]*\\\r?\n)*[^\r\n]*\r?\n)'
    r'(.*?)'
    r'^(CMD(?:[^\r\n]*\\\r?\n)*[^\r\n]*(?:\r?\n|$))'
)

WORKSPACE_DIR_NAME = "project"
BUILD_DATA_DIR_NAME = "build_data"
PATCHES_DIR_NAME = "patches"
REVERSE_PATCH_FLAG = ("-R", "--reverse")
GIT_AUTHOR_CONFIGS = [
    "git config --global user.email setup@susvibes",
    "git config --global user.name SusVibes"
]
BANNED_REINSTALL_FOR_INSTANCE = {}