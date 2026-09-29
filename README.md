# SecureVibeEval

SecureVibeEval evaluates security-aware coding agents on SecureGen, AutoBax,
BaxBench, and SusVibes. It includes model-endpoint runners, benchmark graders,
and a multi-CLI harness for Claude Code, Codex, Copilot, Gemini, and Pi.

Training workflows are maintained separately in
[SecureVibe](https://github.com/MSR-Orchard/SecureVibe). SecureVibeEval can be used independently
of that repository and does not require its GPU training stack.

## Layout

- [`evaluation/`](evaluation/README.md): sequence runners and benchmark grading.
- [`evaluation/harness/`](evaluation/harness/README.md): CLI agents with Docker
  and remote sandbox execution.
- [`data/`](data/README.md): evaluation input inventory and checksums.
- [`dependencies/vendor/`](dependencies/vendor/README.md): bundled mini-swe-agent.

## Quickstart

Evaluation data is available in the public
[SecureVibe dataset on Hugging Face](https://huggingface.co/datasets/dqwang122/SafeVibe/tree/main/raw).

Requirements: Python 3.11 or newer, Bash 4.3 or newer, prepared benchmark
inputs, a model endpoint, and access to task images and an execution backend.
Model serving and sandbox deployment are separate prerequisites.

From this repository's root:

```bash
cd evaluation
./setup.sh

export MODEL=openai/your-model
export LOCAL_BASE=http://127.0.0.1:8200/v1
export OUTPUT_PREFIX=your-model

# Validate inputs and inspect commands before execution.
DRY_RUN=1 ./evaluate.sh
```

The default input directory is `data/raw/` at the repository root. Set
`DATA_DIR` to an absolute path to use another directory. See the
[data inventory](data/README.md) for expected filenames.

The sequence runner uses a remote sandbox by default. Configure
`SANDBOX_BASE_URL` and `SANDBOX_API_KEY` for your deployed service, then run
from `evaluation/`:

```bash
./evaluate.sh
./grade.sh
```

See the [evaluation guide](evaluation/README.md) for benchmark selection,
credentials, concurrency, and grading. Use the
[multi-CLI harness](evaluation/harness/README.md) for Docker or remote-sandbox
CLI evaluation.

## Development checks

After setup, run from `evaluation/`:

```bash
.venv/bin/python -B -m unittest discover -s tests -p test_dependencies.py -v
.venv/bin/python -B -m unittest discover -s tests/grading -v
.venv/bin/python -B -m unittest discover -s harness/tests -v
```

These checks do not launch model or sandbox jobs. The `evaluation/` directory
layout is retained from SecureVibe so runner imports and repository-relative
dependency paths remain stable.

## License

Original project code uses the [MIT License](LICENSE). Bundled third-party
code retains its own notices; see [third-party notices](THIRD_PARTY_NOTICES.md).
Dataset files, credentials, and generated results are excluded from version
control. Benchmark data, task images, and external services retain their
respective access requirements and terms.
