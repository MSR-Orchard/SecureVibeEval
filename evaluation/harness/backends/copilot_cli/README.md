# Copilot CLI backend

Run setup from the evaluation root with `INSTALL_MINISWE_AGENT=0 ./setup.sh`
if you only need the CLI harness and graders. Install GitHub CLI (`gh`) on the
host and authenticate with `gh auth login`; this backend reads `gh auth token`
and does not use token values from `.env`.

Copy `harness/backends/copilot_cli/.env.sample` to the adjacent `.env` to override
`COPILOT_MODEL`. An explicit `--model` takes precedence.

From the evaluation root:

```bash
.venv/bin/python harness/run_benchmark.py --backend copilot_cli --benchmark susvibes --num_instances 10
```

Docker execution requires the host Docker command and daemon. For remote
execution, supply `--execution_backend sandbox` and the sandbox credentials.
The container setup script installs Node 22.23.2 and the locked `@github/copilot` dependency; it requires
root access, `apt-get`, and network access inside the task image.

See the [shared harness guide](../../README.md) for all run options and outputs.
