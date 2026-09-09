# SafeVibeEval evaluation inputs

Evaluation inputs live under `raw/`. From `evaluation/`, the runners default
to this repository's `data/raw/`; override `DATA_DIR` with an absolute path to
use another location.

Evaluation inputs are published under `raw/` in the public
[SafeVibe dataset on Hugging Face](https://huggingface.co/datasets/dqwang122/SafeVibe/tree/main/raw).

## File inventory

- `raw/securegen/securegen_mini_instances.json`: mini-agent evaluation instances.
- `raw/securegen/securegen_tasks.jsonl`: grading tasks.
- `raw/susvibes/susvibes_mini_instances.json`: mini-agent evaluation instances.
- `raw/susvibes/susvibes_tasks.jsonl`: CLI evaluation and grading tasks.
- `raw/autobax/autobax_eval_instances.json`: evaluation instances.
- `raw/autobax/autobax_grading_instances.json`: grading instances and sandbox metadata.
- `raw/baxbench/baxbench_instances.json`: evaluation and grading instances.

The derived SecureGen mini instances have a local checksum but no corresponding
checksum in the upstream manifest.

## Integrity and access

From this directory, run `shasum -a 256 -c SHA256SUMS` to verify the input files.
Download evaluation inputs from the Hugging Face link above. Raw inputs are
excluded from this code repository. The public dataset includes the derived
SecureGen evaluation instances; underlying benchmark terms still apply.

SafeVibe training recipes are available under
[`recipes/` in the same dataset](https://huggingface.co/datasets/dqwang122/SafeVibe/tree/main/recipes).
