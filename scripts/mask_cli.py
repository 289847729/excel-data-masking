#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "python-calamine>=0.3",
#   "xlsxwriter>=3.2",
#   "openpyxl>=3.1",
#   "xlrd>=2.0",
# ]
# ///
"""CLI entry point for zero-plaintext local Excel/CSV inspection and masking."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import engine
import local_ui
import rules


def _configure_stdio_utf8() -> None:
    """Ensure stdout/stderr/stdin handle UTF-8 cleanly on Windows gbk/cp936 consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if callable(reconfig):
            try:
                reconfig(encoding="utf-8", errors="replace")
            except Exception:
                pass
    stdin_reconfig = getattr(sys.stdin, "reconfigure", None)
    if callable(stdin_reconfig):
        try:
            stdin_reconfig(encoding="utf-8-sig", errors="replace")
        except Exception:
            pass


def _print_json(payload: dict[str, Any]) -> None:
    """Print JSON payload safely even on restrictive legacy console encodings."""
    try:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    except UnicodeEncodeError:
        print(json.dumps(payload, ensure_ascii=True, indent=2))


def _load_config(config_arg: str) -> dict[str, Any]:
    """Load structured masking config from a JSON file path or '-' (stdin)."""
    if config_arg == "-":
        raw = sys.stdin.read().lstrip("\ufeff")
    else:
        cfg_path = Path(config_arg)
        if not cfg_path.is_file():
            raise FileNotFoundError(f"Config file not found: {cfg_path.name}")
        raw = cfg_path.read_text(encoding="utf-8-sig")

    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Masking config JSON must be an object")
    return data


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mask_cli.py",
        description="Zero-plaintext high-concurrency Excel/CSV data masking CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # inspect subcommand
    p_inspect = subparsers.add_parser(
        "inspect",
        help="Full-column streaming inspection with zero plaintext output.",
    )
    p_inspect.add_argument(
        "input_path",
        help="Path to input .xlsx/.xlsm/.xls/.xlsb/.csv file.",
    )
    p_inspect.add_argument(
        "--sheet",
        default=None,
        help="Optional sheet name to inspect (defaults to all sheets).",
    )
    p_inspect.add_argument(
        "--chunk-size",
        type=int,
        default=engine.DEFAULT_INSPECT_CHUNK_SIZE,
        help=f"Streaming chunk size in rows (default: {engine.DEFAULT_INSPECT_CHUNK_SIZE}).",
    )
    p_inspect.add_argument(
        "--workers",
        type=int,
        default=engine.DEFAULT_MAX_WORKERS,
        help=f"Max worker processes for large tables (default: {engine.DEFAULT_MAX_WORKERS}).",
    )

    # apply subcommand
    p_apply = subparsers.add_parser(
        "apply",
        help="Apply masking rules via streaming & bounded multiprocessing.",
    )
    p_apply.add_argument(
        "input_path",
        help="Path to input .xlsx/.xlsm/.xls/.xlsb/.csv file.",
    )
    p_apply.add_argument(
        "--config",
        required=True,
        help="Path to JSON masking config file, or '-' to read from stdin.",
    )
    p_apply.add_argument(
        "--output",
        default=None,
        help="Optional output path (defaults to <stem>_masked.xlsx or _masked.csv; never overwrites input).",
    )
    p_apply.add_argument(
        "--workers",
        type=int,
        default=engine.DEFAULT_MAX_WORKERS,
        help=f"Max worker processes for large tables (default: {engine.DEFAULT_MAX_WORKERS}).",
    )
    p_apply.add_argument(
        "--chunk-size",
        type=int,
        default=engine.DEFAULT_APPLY_CHUNK_SIZE,
        help=f"Streaming chunk size in rows (default: {engine.DEFAULT_APPLY_CHUNK_SIZE}).",
    )

    # ui subcommand
    p_ui = subparsers.add_parser(
        "ui",
        help="Launch 100%% offline 127.0.0.1 Web wizard UI for local inspection and masking.",
    )
    p_ui.add_argument(
        "--host",
        default="127.0.0.1",
        help="Loopback host to bind (default: 127.0.0.1; non-loopback addresses are rejected).",
    )
    p_ui.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port to bind (default: 0 for auto-selected free port).",
    )
    p_ui.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open the default web browser.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_stdio_utf8()
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            result = engine.inspect_file(
                input_path=args.input_path,
                sheet_name=args.sheet,
                chunk_size=args.chunk_size,
                max_workers=args.workers,
            )
        elif args.command == "apply":
            config = _load_config(args.config)
            result = engine.apply_masking(
                input_path=args.input_path,
                config=config,
                output_path=args.output,
                workers=args.workers,
                chunk_size=args.chunk_size,
            )
        elif args.command == "ui":
            return local_ui.run_ui(
                host=args.host,
                port=args.port,
                open_browser=not args.no_browser,
            )
        else:
            raise ValueError(f"Unknown command: {args.command}")

        _print_json(result)
        return 0
    except Exception as exc:
        safe_msg = rules.sanitize_error(exc)
        err_payload = {
            "status": "error",
            "command": getattr(args, "command", None),
            "error": safe_msg,
        }
        _print_json(err_payload)
        return 1


if __name__ == "__main__":
    sys.exit(main())
