"""Install the built wheel offline and test it outside the source checkout."""

import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import venv
from pathlib import Path, PurePosixPath


def copy_packaged_tests(sdist, workspace):
    """Use only regular test/script files shipped in the source archive."""
    prefix = sdist.name.removesuffix(".tar.gz")
    with tarfile.open(sdist, "r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if not path.parts or path.parts[0] != prefix or ".." in path.parts:
                raise SystemExit(f"Unexpected source archive path: {member.name}")
            relative = PurePosixPath(*path.parts[1:])
            if not (relative.parts and relative.parts[0] == "tests"
                    or relative == PurePosixPath("scripts/run_tests.py")):
                continue
            if member.isdir():
                continue
            if not member.isfile():
                raise SystemExit(f"Expected a regular test file: {member.name}")
            destination = workspace.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source:
                destination.write_bytes(source.read())
    if not list((workspace / "tests").glob("test_*.py")):
        raise SystemExit("Source archive is missing tests")
    if not (workspace / "scripts" / "run_tests.py").is_file():
        raise SystemExit("Source archive is missing scripts/run_tests.py")


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
            "assert not importlib.metadata.requires('routescope'), 'Unexpected runtime dependencies'; "
            "print('Installed package:', routescope.__file__)"
        ))
        run(str(script), "--help")
        run(str(python), "-I", "-m", "routescope", "--help")
        copy_packaged_tests(sdists[0], workspace)
        run(str(python), "-I", "-W", "error", str(workspace / "scripts" / "run_tests.py"))


if __name__ == "__main__":
    main()
