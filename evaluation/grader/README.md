# Grading runtime

Run all configured benchmarks with `./grade.sh` from the evaluation
root. Each benchmark also provides `grade.py`; SecureGen and AutoBax additionally
provide `grade_plans.py`. Run an entrypoint with `--help` for its full interface.
The entrypoints resolve their implementation paths independently of the current
working directory.

- [SecureGen](securegen/README.md): functional/security grading and security-plan grading.
- [AutoBax](autobax/README.md): sandbox execution and security-plan grading.
- [BaxBench](baxbench/README.md): sandbox execution of generated applications.
- [SusVibes](susvibes/README.md): grading predicted repository patches.

Each benchmark keeps scoring and backend implementations in its `src/` or
`susvibes/` package. Scenario tests and fixtures are documented in the benchmark
guides above.

Regression tests live in `../tests/grading/`, outside the deployed grading runtime.
From the evaluation root, using the environment installed by `setup.sh`:

```bash
.venv/bin/python -m unittest discover -s tests/grading -v
```

These checks use temporary synthetic inputs and do not call model APIs or run
remote sandbox jobs. Full benchmark runs require prepared datasets and backend access.

AutoBax and BaxBench upload `sandbox-requirements.lock` into each sandbox and
install that exact Python dependency set before grading. The sandbox needs
Python 3.10 or newer. Installation failure aborts that sample instead of using
an unknown preinstalled dependency set. To update the lock from the evaluation
root:

```bash
uv pip compile --python-version 3.10 --universal grader/sandbox-requirements.in --output-file grader/sandbox-requirements.lock
```

The host environment continues to use `../requirements.lock`. OS packages and
scenario-specific tools are provided by benchmark images (or the existing
scenario package commands), independently of these Python locks.
