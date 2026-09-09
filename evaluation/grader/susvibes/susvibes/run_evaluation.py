import argparse
from pathlib import Path

from susvibes.constants import *
from susvibes.tasks import TasksHandler, get_summary, print_summary
from susvibes.utils import load_file, save_file

def _run_evaluation(
    run_id: str,
    dataset_path: Path,
    predictions: list,
    strategy: str,
    max_workers: int,
    force: bool = False,
    backend: str = "docker",
    env_spec_id: str = "default"
):
    if backend == "sandbox":
        # Fail fast on missing credentials: otherwise every instance raises inside
        # build_runtime_deployment and gets mislabeled model_patch_error. One clear
        # error up front beats N confusing per-instance reports.
        from susvibes.sandbox import sandbox_config, SandboxError
        try:
            sandbox_config()
        except SandboxError as e:
            raise SystemExit(f"--backend sandbox: {e}")
    dataset = load_file(dataset_path)
    handler = TasksHandler(dataset, strategy, run_id, backend, env_spec_id)
    handler.run_evaluation_threadpool(predictions, max_workers, force)
    for model_name_or_path, model_reports in handler.reports.items():
        eval_summary = get_summary(dataset, model_reports, strategy)
        summary_path = EVALUATION_LOG_DIR / run_id / strategy / model_name_or_path / LOG_SUMMARY
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        save_file(eval_summary, summary_path)
        print(f"\n=== {model_name_or_path} ===")
        print_summary(eval_summary)
        print(f"Summary saved to {summary_path}.")
    
def run_evaluation(
    run_id: str,
    dataset_path: Path,
    predictions_path: Path,
    strategy: str,
    max_workers: int,
    force: bool = False,
    backend: str = "docker",
    env_spec_id: str = "default"
):
    predictions = load_file(predictions_path)
    if isinstance(predictions, dict):
        predictions = list(predictions.values())
    _run_evaluation(run_id, dataset_path, predictions, strategy,
              max_workers, force, backend, env_spec_id)
    

def main():
    """Entry point for the susvibes-eval command."""
    parser = argparse.ArgumentParser(description="Run evaluation for agent predictions.")
    parser.add_argument(
        "--run_id",
        type=str,
        default="default",
        help="Unique ID that identifies the run.",
    )
    parser.add_argument(
        "--predictions_path",
        type=Path,
        help="Path to the predictions file.",
    )
    parser.add_argument(
        "--dataset_path",
        type=Path,
        help="Path to the dataset file (defaults to the configured dataset).",
    )
    parser.add_argument(
        "--max_workers",
        type=int,
        default=5,
        help="Number of threads to use for environment setup.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-run the environment setup.",
    )
    parser.add_argument(
        "--backend",
        type=str,
        default="docker",
        choices=["docker", "sandbox"],
        help="Grading backend: local Docker (default) or the remote sandbox service "
             "(needs SANDBOX_BASE_URL / SANDBOX_API_KEY).",
    )
    parser.add_argument(
        "--env_spec_id",
        type=str,
        default="default",
        help="Which env_specs/<id>/components.json to load the per-instance test-log "
             "parsers from (default: 'default'; use 'train' for the merged train set).",
    )
    
    parser.add_argument(
        "--strategy", default="generic",
        choices=["generic", "self-selection", "oracle", "feedback-driven", "sec-test"],
        help="Strategy used when generating the predictions being graded.",
    )
    parser.add_argument(
        "--agent", default="swe-agent", choices=["swe-agent", "mini-swe-agent"],
        help="Compatibility option for sequence scripts; predictions use the same format.",
    )

    args = parser.parse_args()
    # --run_id only sets the eval-log output directory
    # (<evaluation-log-root>/<run_id>/...); it does not select the input dataset.
    dataset_path = args.dataset_path or DEFAULT_DATASET_PATH
    run_evaluation(args.run_id, dataset_path, args.predictions_path, args.strategy,
                   args.max_workers, args.force, args.backend, args.env_spec_id)

if __name__ == "__main__":
    main()
