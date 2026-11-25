#!/usr/bin/env python3
"""Cross-platform zero-dependency installer for the excel-data-masking skill."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from typing import Any

SKILL_NAME = "excel-data-masking"
DEPENDENCIES = ("python-calamine", "xlsxwriter", "openpyxl", "xlrd")
IGNORED_NAMES = frozenset({".venv", "__pycache__", ".DS_Store", ".pytest_cache"})

# Ordered by preference when selecting primary_skill_dir in auto/all modes.
PLATFORM_SPECS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("antigravity", (".gemini", "config"), (".gemini", "config", "skills", SKILL_NAME)),
    ("claude", (".claude",), (".claude", "skills", SKILL_NAME)),
    ("codex", (".codex",), (".codex", "skills", SKILL_NAME)),
    ("cursor", (".cursor",), (".cursor", "skills", SKILL_NAME)),
    ("gemini", (".gemini",), (".gemini", "skills", SKILL_NAME)),
    ("opencode", (".config", "opencode"), (".config", "opencode", "skills", SKILL_NAME)),
)
PLATFORM_MAP: dict[str, tuple[str, ...]] = {
    name: install_parts for name, _, install_parts in PLATFORM_SPECS
}

UV_WARMUP_TIMEOUT_SEC = 180
PIP_INSTALL_TIMEOUT_SEC = 240
CLI_CHECK_TIMEOUT_SEC = 30


def _configure_stdio_utf8() -> None:
    """Ensure stdout/stderr handle UTF-8 cleanly on Windows legacy consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if callable(reconfig):
            try:
                reconfig(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _print_json(payload: dict[str, Any]) -> None:
    """Print JSON payload safely regardless of console encoding restrictions."""
    try:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    except UnicodeEncodeError:
        print(json.dumps(payload, ensure_ascii=True, indent=2))


def _norm_realpath(path: Path) -> str:
    """Return normalized real path string suitable for cross-platform equality checks."""
    return os.path.normcase(os.path.realpath(path))


def _validate_source_dir(source_dir: Path) -> None:
    """Verify the source skill directory contains required entry files."""
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source skill directory does not exist: {source_dir}")
    if not (source_dir / "SKILL.md").is_file():
        raise FileNotFoundError(f"Missing SKILL.md in source directory: {source_dir}")
    if not (source_dir / "scripts" / "mask_cli.py").is_file():
        raise FileNotFoundError(
            f"Missing scripts/mask_cli.py in source directory: {source_dir}"
        )


def _detect_platforms(home_dir: Path) -> list[str]:
    """Detect existing AI agent configuration roots under home_dir."""
    detected: list[str] = []
    for name, detect_parts, _ in PLATFORM_SPECS:
        if home_dir.joinpath(*detect_parts).is_dir():
            detected.append(name)
    return detected


def _resolve_targets(
    home_dir: Path, target_arg: str, detected_platforms: list[str]
) -> list[Path]:
    """Resolve installation target directories from --target CLI argument."""
    raw = target_arg.strip()
    if not raw:
        raise ValueError("--target cannot be empty")

    candidates: list[Path] = []
    if raw == "auto":
        if detected_platforms:
            for name in detected_platforms:
                candidates.append(home_dir.joinpath(*PLATFORM_MAP[name]))
        else:
            candidates.append(home_dir / ".agents" / "skills" / SKILL_NAME)
    elif raw == "all":
        for name, _, install_parts in PLATFORM_SPECS:
            candidates.append(home_dir.joinpath(*install_parts))
    elif raw.startswith("workspace:"):
        ws_dir = raw[len("workspace:") :].strip()
        if not ws_dir:
            raise ValueError("workspace:<dir> requires a non-empty directory path")
        candidates.append(
            Path(ws_dir).expanduser().resolve() / ".agents" / "skills" / SKILL_NAME
        )
    else:
        tokens = [item.strip() for item in raw.split(",") if item.strip()]
        if not tokens:
            raise ValueError(f"Invalid --target specification: {target_arg}")
        for token in tokens:
            if token.startswith("workspace:"):
                ws_dir = token[len("workspace:") :].strip()
                if not ws_dir:
                    raise ValueError("workspace:<dir> requires a non-empty directory path")
                candidates.append(
                    Path(ws_dir).expanduser().resolve()
                    / ".agents"
                    / "skills"
                    / SKILL_NAME
                )
            else:
                key = token.lower()
                if key not in PLATFORM_MAP:
                    supported = ", ".join(PLATFORM_MAP.keys())
                    raise ValueError(
                        f"Unknown target platform '{token}'. Supported: auto, all, {supported}, workspace:<dir>"
                    )
                candidates.append(home_dir.joinpath(*PLATFORM_MAP[key]))

    # Deduplicate while preserving order using normalized real paths.
    unique_targets: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        norm = _norm_realpath(path)
        if norm not in seen:
            seen.add(norm)
            unique_targets.append(path)
    return unique_targets


def _copy_skill(source_dir: Path, dest_dir: Path) -> bool:
    """Safely copy skill directory to dest_dir, returning False if skipped (same path)."""
    src_norm = _norm_realpath(source_dir)
    dst_norm = _norm_realpath(dest_dir)
    if src_norm == dst_norm:
        return False

    if (dest_dir.exists() or dest_dir.is_symlink()) and not dest_dir.is_dir():
        dest_dir.unlink()

    dest_dir.mkdir(parents=True, exist_ok=True)

    # Refresh existing installation cleanly while preserving any pre-built .venv.
    for entry in dest_dir.iterdir():
        if entry.name == ".venv":
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()

    dst_parent_norm = _norm_realpath(dest_dir.parent)
    dst_name = dest_dir.name

    def _ignore(dirpath: str, names: list[str]) -> set[str]:
        ignored = {n for n in names if n in IGNORED_NAMES or n.endswith(".pyc")}
        # Guard against recursive copy if dest_dir happens to live inside source_dir.
        if os.path.normcase(os.path.realpath(dirpath)) == dst_parent_norm and dst_name in names:
            ignored.add(dst_name)
        return ignored

    shutil.copytree(source_dir, dest_dir, ignore=_ignore, dirs_exist_ok=True)
    return True


def _run_silent(cmd: list[str], timeout_sec: int) -> subprocess.CompletedProcess[str] | None:
    """Run subprocess non-interactively without leaking output to stdout."""
    try:
        return subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _find_venv_python(venv_dir: Path) -> Path | None:
    """Locate Python interpreter inside a virtual environment across platforms."""
    candidates = [
        venv_dir / "Scripts" / "python.exe",
        venv_dir / "bin" / "python",
        venv_dir / "bin" / "python3",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _prepare_runtime(primary_skill_dir: Path, skip_deps: bool) -> tuple[str, list[str]]:
    """Prepare runtime environment and return (runtime_mode, launch_args)."""
    primary_cli = primary_skill_dir / "scripts" / "mask_cli.py"
    uv_exe = shutil.which("uv")

    if skip_deps:
        if uv_exe:
            return "skipped", ["uv", "run", "--script", str(primary_cli), "ui"]
        return "skipped", [sys.executable, str(primary_cli), "ui"]

    # 1. Prefer uv standalone PEP 723 script runtime when available and working.
    if uv_exe:
        res = _run_silent(
            [uv_exe, "run", "--script", str(primary_cli), "--help"],
            timeout_sec=UV_WARMUP_TIMEOUT_SEC,
        )
        if res is not None and res.returncode == 0:
            return "uv", ["uv", "run", "--script", str(primary_cli), "ui"]

    # 2. Fallback: create isolated .venv under primary_skill_dir and install dependencies.
    venv_dir = primary_skill_dir / ".venv"
    venv_existed = venv_dir.exists()
    venv_python = _find_venv_python(venv_dir) if venv_existed else None

    if venv_python is None:
        try:
            venv.create(venv_dir, with_pip=True)
            venv_python = _find_venv_python(venv_dir)
        except Exception:
            venv_python = None

    if venv_python is not None:
        pip_res = _run_silent(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                *DEPENDENCIES,
            ],
            timeout_sec=PIP_INSTALL_TIMEOUT_SEC,
        )
        if pip_res is not None and pip_res.returncode == 0:
            cli_res = _run_silent(
                [str(venv_python), str(primary_cli), "--help"],
                timeout_sec=CLI_CHECK_TIMEOUT_SEC,
            )
            if cli_res is not None and cli_res.returncode == 0:
                return "venv", [str(venv_python), str(primary_cli), "ui"]

        # If pip failed (e.g. offline), reuse pre-existing venv only if deps are already present.
        if venv_existed:
            dep_res = _run_silent(
                [
                    str(venv_python),
                    "-c",
                    "import python_calamine, xlsxwriter, openpyxl, xlrd",
                ],
                timeout_sec=CLI_CHECK_TIMEOUT_SEC,
            )
            cli_res = _run_silent(
                [str(venv_python), str(primary_cli), "--help"],
                timeout_sec=CLI_CHECK_TIMEOUT_SEC,
            )
            if (
                dep_res is not None
                and dep_res.returncode == 0
                and cli_res is not None
                and cli_res.returncode == 0
            ):
                return "venv", [str(venv_python), str(primary_cli), "ui"]
        else:
            # Clean up incomplete newly created venv before falling back to system Python.
            shutil.rmtree(venv_dir, ignore_errors=True)

    # 3. Offline/restricted fallback: verify current sys.executable can run mask_cli.py.
    sys_res = _run_silent(
        [sys.executable, str(primary_cli), "--help"],
        timeout_sec=CLI_CHECK_TIMEOUT_SEC,
    )
    if sys_res is not None and sys_res.returncode == 0:
        return "system_python", [sys.executable, str(primary_cli), "ui"]

    detail = (sys_res.stderr or sys_res.stdout or "").strip() if sys_res else "execution failed"
    raise RuntimeError(
        f"Failed to prepare runtime environment for {primary_cli}: {detail[:300]}"
    )


def _format_launch_command(launch_args: list[str]) -> str:
    """Format launch_args into a single-line double-quoted command compatible with Windows and POSIX."""
    parts: list[str] = []
    for idx, arg in enumerate(launch_args):
        needs_quotes = (
            idx > 0 and arg not in ("run", "--script", "ui")
        ) or (
            idx == 0 and arg != "uv"
        ) or any(ch in arg for ch in (' ', '\t', '"', '\\', '/', ':', '(', ')', '&', ';', '$')) or not arg.isascii()

        if needs_quotes:
            escaped = arg.replace('"', '\\"')
            parts.append(f'"{escaped}"')
        else:
            parts.append(arg)
    return " ".join(parts)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto_install.py",
        description="Cross-platform auto-installer and runtime preparer for excel-data-masking.",
    )
    parser.add_argument(
        "--home",
        default=None,
        help="Override user home directory for platform detection (defaults to Path.home()).",
    )
    parser.add_argument(
        "--target",
        default="auto",
        help=(
            "Install target: 'auto', 'all', comma-separated platform names "
            "(antigravity,claude,codex,cursor,gemini,opencode), or 'workspace:<dir>'."
        ),
    )
    parser.add_argument(
        "--skip-deps",
        action="store_true",
        help="Skip dependency warmup/venv setup (for fast file-copy and detection testing).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_stdio_utf8()
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        source_dir = Path(__file__).resolve().parent.parent
        _validate_source_dir(source_dir)

        home_dir = (
            Path(args.home).expanduser().resolve()
            if args.home is not None
            else Path.home().resolve()
        )

        detected_platforms = _detect_platforms(home_dir)
        target_paths = _resolve_targets(home_dir, args.target, detected_platforms)

        installed_paths: list[str] = []
        for dest_dir in target_paths:
            _copy_skill(source_dir, dest_dir)
            installed_paths.append(str(dest_dir))

        primary_skill_dir = Path(installed_paths[0])
        runtime_mode, launch_args = _prepare_runtime(
            primary_skill_dir=primary_skill_dir,
            skip_deps=args.skip_deps,
        )
        launch_command = _format_launch_command(launch_args)

        _print_json(
            {
                "status": "ok",
                "detected_platforms": detected_platforms,
                "installed_paths": installed_paths,
                "primary_skill_dir": str(primary_skill_dir),
                "runtime_mode": runtime_mode,
                "launch_args": launch_args,
                "launch_command": launch_command,
            }
        )
        return 0
    except Exception as exc:
        _print_json(
            {
                "status": "error",
                "error": str(exc),
            }
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
