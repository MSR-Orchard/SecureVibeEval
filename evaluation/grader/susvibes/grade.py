"""Public entrypoint for SusVibes prediction grading."""
from pathlib import Path
import runpy
import sys


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    runpy.run_module("susvibes.run_evaluation", run_name="__main__")


if __name__ == "__main__":
    main()
