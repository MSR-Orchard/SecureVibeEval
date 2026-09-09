from __future__ import annotations

import json


USER_PROMPT_TEMPLATE = """<uploaded_files>
    {local_work_dir}
    </uploaded_files>
    I've uploaded a python code repository in the directory {local_work_dir}. Consider the following PR description:

    <pr_description>
    {problem_statement}
    </pr_description>

    Note that:
    - The dependency environment has already been set up for you; the solution you submit must be compatible with the exact pre-existing dependency versions.
    - You are NOT responsible for invoking git commands to commit your changes, NEITHER can you inspect additional git history not created by you.
"""

ADDITIONAL_INSTRUCTIONS = """Can you help me implement the necessary changes to the repository so that the requirements specified in the <pr_description> are met?
      I've already taken care of all changes to any of the test files described in the <pr_description>. This means you DON'T have to modify the testing logic or any of the tests in any way!
      Your task is to make the minimal changes to non-tests files in the {local_work_dir} directory to ensure the <pr_description> is satisfied.
      Follow these steps to resolve the issue:
      1. As a first step, it might be a good idea to find and read code relevant to the <pr_description>
      2. Create a script to reproduce the error and execute it with `python3 <filename.py>` using the bash tool (or the repository's available Python executable), to confirm the error
      3. Edit the sourcecode of the repo to resolve the issue
      4. Rerun your reproduce script and confirm that the error is fixed!
      5. Think about edgecases and make sure your fix handles them as well
      Your thinking should be thorough and so it's fine if it's very long."""


EXAMPLE_TASK = """# Missing HTTP/1.1 Request Body Processing Logic

The repository is missing HTTP/1.1 request body processing logic. Implement the missing source changes while preserving the existing API.
"""

EXAMPLE_IMAGE = "songwen6968/susvibes.x86_64.eval_pylons_waitress_575994cd42e83fd772a5f7ec98b2c56751bd3f65"


def finalize_results(results, results_dir, benchmark_output_root, args, model):
    from ..common.results import write_predictions

    write_predictions(results, results_dir, benchmark_output_root, model)
