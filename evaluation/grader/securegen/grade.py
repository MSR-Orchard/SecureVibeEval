"""Public entrypoint for securegen prediction grading."""
from pathlib import Path
import runpy
import sys
import os

def main():
    source = Path(os.environ.get("SECUREGEN_SRC", Path(__file__).resolve().parent / "src"))
    sys.path.insert(0, str(source))
    runpy.run_path(str(source / "grade.py"), run_name="__main__")


if __name__ == "__main__":
    main()
