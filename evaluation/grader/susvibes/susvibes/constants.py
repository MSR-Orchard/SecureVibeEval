import os
from enum import Enum
from pathlib import Path

root_dir = Path(__file__).parent.parent
current_dir = Path(__file__).parent

DATASETS_DIR = root_dir / "datasets"
DEFAULT_DATASET_PATH = DATASETS_DIR / "default" / "susvibes_dataset.jsonl"

ENV_SPECS_DIR = current_dir / "env_specs"

def get_env_spec_path(name: str, run_id: str = "default") -> Path:
    base = ENV_SPECS_DIR / run_id
    paths = {
        'components': base / 'components.json',
    }
    return paths[name]

EVALUATION_LOG_DIR = Path(
    os.environ.get(
        "SUSVIBES_EVALUATION_LOG_DIR",
        root_dir / "logs/run_evaluation",
    )
).expanduser()
LOG_SUMMARY = "summary.json"

CONTAINER_RUN_TIMEOUT = 1800
CONTAINER_MEM_LIMIT = "{}g".format(
    min(int(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024 ** 3) * 0.75), 16))
CONTAINER_CPU_LIMIT = min(int(os.cpu_count() * 0.75), 16)

DOCKERHUB_USERNAME = "songwen6968"
HF_DATASET_REPO = "songwen6968/SusVibes"
HF_DATASET_FILENAME = "susvibes_dataset.jsonl"
ARCH = os.uname().machine

# Pull-through mirror for Docker Hub images. mirror.gcr.io is Google's public, rate-limit-free
# cache of Docker Hub (the same one the SWE-bench harness uses for sweb.eval.* images). Routing
# the songwen6968/susvibes.* images through it avoids Docker Hub rate limits and lets every node
# pull from a fast cache, so sandboxes stop sitting Pending on cold pulls. Set "" to disable.
IMAGE_MIRROR = os.environ.get("SUSVIBES_IMAGE_MIRROR", "mirror.gcr.io")

class Strategies(Enum):
    GENERIC = "generic"
    SELF_SELECTION = "self-selection"
    ORACLE = "oracle"
    FEEDBACK_DRIVEN = "feedback-driven"
    SEC_TEST = "sec-test"

class PredictionKeys(Enum):
    INSTANCE_ID = "instance_id"
    PREDICTION = "model_patch"
    MODEL = "model_name_or_path"

class EvalStatus(Enum):
    NO_PATCH = "no_patch"
    MODEL_PATCH_ERROR = "model_patch_error"
    STARTUP_ERROR = "startup_error"
    TIMEOUT = "timeout"
    COMPLETION = "completion"
    ERROR = "error"  # internal/transient failure (e.g. Docker daemon error under load)
    SKIPPED = "skipped"  # no env-spec available for this instance; not evaluated

# Container command for the generated-sec-test run (flags.gen_test instances): run the
# baked sectests.sh, then print the per-case JSON pass-map for gen_sec parsing.
GEN_SEC_TEST_COMMAND = "bash sectests.sh ; cat secresults.json"
