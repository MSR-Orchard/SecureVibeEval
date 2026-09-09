"""Public entrypoint for autobax security-plan grading."""
from pathlib import Path
import runpy
import sys


def main():
    source = Path(__file__).resolve().parent / "src"
    sys.path.insert(0, str(source))
    runpy.run_path(str(source / "grade_security_plans.py"), run_name="__main__")


if __name__ == "__main__":
    main()
