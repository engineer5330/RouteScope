"""Install the built wheel offline and test it outside the source checkout."""

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def main():
    print(f"Checking installation: {platform.platform()}, {platform.machine()}, Python {sys.version.split()[0]}", flush=True)
    root = Path(__file__).resolve().parents[1]
    wheels = list((root / "dist").glob("*.whl"))
    sdists = list((root / "dist").glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("Expected one wheel and one sdist in dist/; run python -m build first")

    with tempfile.TemporaryDirectory(prefix="routescope-install-") as directory:
        workspace = Path(directory)
        environment = workspace / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / "bin" / "python"
        script = environment / "bin" / "routescope"
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env["PYTHONWARNINGS"] = "error"
        env["PIP_NO_INDEX"] = "1"
        env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

        def run(*arguments):
            subprocess.run(arguments, cwd=workspace, env=env, check=True)

        run(str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0]))
        run(str(python), "-I", "-m", "pip", "check")
        run(str(python), "-I", "-c", (
            "import importlib.metadata, pathlib, sys, routescope; "
            "assert pathlib.Path(routescope.__file__).is_relative_to(pathlib.Path(sys.prefix)); "
            "assert importlib.metadata.version('routescope') == routescope.__version__; "
            "print('Installed package:', routescope.__file__)"
        ))
        run(str(script), "--help")
        run(str(python), "-I", "-m", "routescope", "--help")
        shutil.copytree(root / "tests", workspace / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        (workspace / "scripts").mkdir()
        shutil.copy2(root / "scripts" / "run_tests.py", workspace / "scripts" / "run_tests.py")
        run(str(python), "-I", "-W", "error", str(workspace / "scripts" / "run_tests.py"))


if __name__ == "__main__":
    main()
