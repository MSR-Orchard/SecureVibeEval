from typing import Any, Dict


def build_prompt(prompts_module, instance: Dict[str, Any], local_work_dir: str) -> str:
    if hasattr(prompts_module, "build_prompt"):
        return prompts_module.build_prompt(instance, local_work_dir)

    problem_statement = instance.get("problem_statement", "")
    prompt = prompts_module.USER_PROMPT_TEMPLATE.format(
        local_work_dir=local_work_dir,
        problem_statement=problem_statement,
    )
    instructions = prompts_module.ADDITIONAL_INSTRUCTIONS.format(
        local_work_dir=local_work_dir
    )
    return prompt + "\n" + instructions
