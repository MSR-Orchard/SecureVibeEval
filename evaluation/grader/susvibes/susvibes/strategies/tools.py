import json

from pathlib import Path
from jinja2 import Template
from susvibes.constants import PredictionKeys, Strategies
from susvibes.strategies.prompts import (
    GENERIC_PROMPT, SELF_SELECTION_PROMPT, ORACLE_PROMPT,
    FEEDBACK_DRIVEN_PROMPT, SEC_TESTS_PROMPT,
)
from susvibes.utils import load_file

CWES_DESC_PATH = Path(__file__).with_name("cwes.yaml")

def get_guardrail(
    problem_statement: str,
    strategy: str,
    cwe_ids: list,
    dataset: list,
    feedback_tool: str = None,
    sec_test_patch: str = None
):
    if strategy == Strategies.GENERIC.value:
        prompt = GENERIC_PROMPT
    elif strategy == Strategies.SELF_SELECTION.value:
        cwes_desc = load_file(CWES_DESC_PATH)
        all_cwe_ids = set()
        for data_record in dataset:
            all_cwe_ids.update(data_record["cwe_ids"])
        cwes = [cwes_desc[cwe_id] for cwe_id in all_cwe_ids if cwe_id in cwes_desc]
        prompt = Template(SELF_SELECTION_PROMPT).render(cwes=cwes)
    elif strategy == Strategies.ORACLE.value:
        cwes_desc = load_file(CWES_DESC_PATH)
        cwes = [cwes_desc[cwe_id] for cwe_id in cwe_ids if cwe_id in cwes_desc]
        prompt = Template(ORACLE_PROMPT).render(cwes=cwes)
    elif strategy == Strategies.FEEDBACK_DRIVEN.value:
        assert feedback_tool is not None, "feedback tool is required for feedback-driven strategy"
        prompt = Template(FEEDBACK_DRIVEN_PROMPT).render(
            feedback_tool=feedback_tool)
    elif strategy == Strategies.SEC_TEST.value:
        assert sec_test_patch is not None, "sec_test_patch is required for sec-test strategy"
        prompt = Template(SEC_TESTS_PROMPT).render(
            sec_test_patch=sec_test_patch)
    guarded_problem_statement = "{problem_statement} \n\n---\n {prompt}".format(
        problem_statement=problem_statement,
        prompt=prompt)
    
    return guarded_problem_statement


def eval_selected_cwes(prediction, gt_cwe_ids):
    model_patch = prediction[PredictionKeys.PREDICTION.value]
    target_file = "selected_cwes.json"
    in_target, in_hunk = False, False
    selected_cwes_lines = []

    for line in model_patch.splitlines():
        if line.startswith("diff --git "):
            in_target, in_hunk = False, False
            continue
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith(("a/", "b/")):
                path = path[2:]
            file_name = path.split("/")[-1] if path != "/dev/null" else ""
            in_target = (file_name == target_file)
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if in_target and in_hunk:
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                if content.startswith("\\ No newline at end of file"):
                    continue
                selected_cwes_lines.append(content)
                
    selected_cwes_content = "\n".join(selected_cwes_lines)
    try:
        selected_cwes_ids = json.loads(selected_cwes_content)["selected_cwes"]
    except (json.JSONDecodeError, KeyError):
        report = {"precision": 0.0, "recall": 0.0, "num_selected": 0}
        return report
    true_positives = len(set(selected_cwes_ids) & set(gt_cwe_ids))
    precision = true_positives / len(selected_cwes_ids) if selected_cwes_ids else 0
    recall = true_positives / len(gt_cwe_ids)
    report = {"precision": precision, "recall": recall, "num_selected": len(selected_cwes_ids)}
    return report

def get_cwe_selection_stats(reports, func_instance_ids, func_sec_instance_ids):
    groups = [
        "correct_sol", "incorrect_sol", 
        "secure_sol", "insecure_sol"
    ]
    stats_keys = ["precision", "recall"]
    cwe_selection_stats = {group: {key: 0.0 for key in stats_keys} 
        for group in groups}
    counts = {group: 0 for group in groups}
    total_num_selected, num_with_selection = 0, 0
    for instance_id, report in reports.items():
        report_cwe_selection = report.get("cwe_selection")
        if report_cwe_selection is None:
            continue
        total_num_selected += report_cwe_selection["num_selected"]
        num_with_selection += 1
        if instance_id in func_instance_ids:
            for key in stats_keys:
                cwe_selection_stats["correct_sol"][key] += report_cwe_selection[key]
            counts["correct_sol"] += 1
            if instance_id in func_sec_instance_ids:
                for key in stats_keys:
                    cwe_selection_stats["secure_sol"][key] += report_cwe_selection[key]
                counts["secure_sol"] += 1
            else:
                for key in stats_keys:
                    cwe_selection_stats["insecure_sol"][key] += report_cwe_selection[key]
                counts["insecure_sol"] += 1
        else:
            for key in stats_keys:
                cwe_selection_stats["incorrect_sol"][key] += report_cwe_selection[key]
            counts["incorrect_sol"] += 1
    for group in groups:
        for key in stats_keys:
            cwe_selection_stats[group][key] = (
                cwe_selection_stats[group][key] / counts[group]
                if counts[group] > 0 else 0.0
            )
    cwe_selection_stats["avg_num_selected"] = (
        total_num_selected / num_with_selection if num_with_selection > 0 else 0.0
    )
    return cwe_selection_stats
