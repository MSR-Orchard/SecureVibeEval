# SecureVibeEval

SecureVibeEval evaluates security-aware coding agents on PatchEval-Gen
(SecureGen in the code), AutoBaxBench, BaxBench, and SusVibes. It includes model-endpoint runners, benchmark graders,
and a multi-CLI harness for Claude Code, Codex, Copilot, Gemini, and Pi.

Training workflows are maintained separately in
[SecureVibe](https://github.com/MSR-Orchard/SecureVibe). SecureVibeEval can be used independently
of that repository and does not require its GPU training stack.

## Benchmarks and datasets

The table describes the prepared benchmarks supported by SecureVibeEval.
Task counts refer to benchmark instances, not generated trajectories or the
full upstream collections. Source links point to the original projects;
prepared evaluation inputs are available in the
[SecureVibe dataset](https://huggingface.co/datasets/dqwang122/SafeVibe/tree/main/raw).

| Benchmark / source | Runtime identifier | Tasks | Task type | Languages | CWE categories |
| --- | --- | ---: | --- | --- | ---: |
| PatchEval-Gen (from [PatchEval](https://github.com/bytedance/PatchEval)) | `securegen` | 200 | Feature implementation in existing repositories | 3: JavaScript, Python, Go | 39 |
| AutoBaxBench (from [AutoBaxBuilder](https://github.com/eth-sri/autobaxbuilder)) | `autobax` | 560 | Backend web application generation from scratch | 6: JavaScript, Python, Go, Ruby, Rust, PHP | 9 |
| [BaxBench](https://github.com/logic-star-ai/baxbench) | `baxbench` | 392 | Backend web application generation from scratch | 6: JavaScript, Python, Go, Ruby, Rust, PHP | 13 |
| [SusVibes](https://github.com/LeiLiLab/susvibes) | `susvibes` | 186 | Security-sensitive feature implementation in existing repositories | Python | 76 |

PatchEval-Gen adapts PatchEval vulnerability-repair instances into feature
implementation tasks and removes instances sharing CVE IDs with SusVibes.
AutoBaxBench covers 40 scenarios across 14 framework/language configurations;
BaxBench covers 28 non-overlapping scenarios across 14 configurations.
CWE counts denote distinct vulnerability categories, and an instance may
contain multiple CWEs.

**FuncPass** is pass@1 on functional tests. **SecPass** is
pass@1 on solutions that pass both functional and security tests.

See the [data guide](data/README.md) for the expected input files, runtime
name mapping, and checksum verification. Benchmark data and task images remain
subject to their upstream access requirements and terms.

## Supported agent harnesses

All six agent integrations support the four security benchmarks. The CLI
harness selects the agent backend and benchmark independently.

| Agent harness | Entry point / backend | PatchEval-Gen (`securegen`) | AutoBaxBench (`autobax`) | BaxBench (`baxbench`) | SusVibes (`susvibes`) |
| --- | --- | :---: | :---: | :---: | :---: |
| [mini-swe-agent](evaluation/README.md) | `evaluation/evaluate.sh` | Yes | Yes | Yes | Yes |
| [Claude Code](evaluation/harness/backends/claude_code/README.md) | `--backend claude_code` | Yes | Yes | Yes | Yes |
| [Codex CLI](evaluation/harness/backends/codex_cli/README.md) | `--backend codex_cli` | Yes | Yes | Yes | Yes |
| [GitHub Copilot CLI](evaluation/harness/backends/copilot_cli/README.md) | `--backend copilot_cli` | Yes | Yes | Yes | Yes |
| [Gemini CLI](evaluation/harness/backends/gemini_cli/README.md) | `--backend gemini_cli` | Yes | Yes | Yes | Yes |
| [Pi CLI](evaluation/harness/backends/pi_cli/README.md) | `--backend pi_cli` | Yes | Yes | Yes | Yes |

The mini-swe-agent sequence uses a configured model endpoint and defaults to
remote sandbox execution. CLI agents run through
`evaluation/harness/run_benchmark.py` or `run_benchmark_parallel.py` and
support local Docker (the default) or a remote sandbox. Each CLI requires its
own credentials and model configuration; see its linked setup guide.

For example, run Codex CLI on BaxBench from `evaluation/`:

```bash
.venv/bin/python harness/run_benchmark.py \
  --backend codex_cli --benchmark baxbench \
  --execution_backend docker --num_instances 10
```

These entries describe implemented integrations. Running them requires the
benchmark inputs, task images, agent credentials, and execution backend.
See the [multi-CLI harness guide](evaluation/harness/README.md) for model
selection, parallel runs, and output formats, and the
[evaluation guide](evaluation/README.md) for grading.

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
