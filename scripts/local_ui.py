"""Offline local 127.0.0.1 Web wizard UI for zero-plaintext Excel/CSV masking.

Pure Python standard library implementation (Python 3.11+ / 3.13 compatible,
zero external dependencies, zero external network requests, no legacy `cgi`).
"""

from __future__ import annotations

import atexit
import ipaddress
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import uuid
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import engine
import rules

_UPLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming chunks
_DOWNLOAD_CHUNK_SIZE = 64 * 1024  # 64 KiB streaming chunks


def is_loopback_host(host: str) -> bool:
    """Return True only for strict local loopback hostnames or IP addresses."""
    cleaned = (host or "").strip()
    if not cleaned:
        return False
    if cleaned.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def _sanitize_upload_filename(raw_name: str) -> str:
    """Extract a safe basename and validate its supported spreadsheet extension."""
    decoded = unquote(raw_name or "").strip()
    # Handle both POSIX and Windows path separators safely
    base = PureWindowsPath(decoded.replace("/", "\\")).name
    base = Path(base).name
    if not base or base in {".", ".."}:
        raise ValueError("Invalid upload filename")

    ext = Path(base).suffix.lower()
    if ext not in engine.SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension '{ext}'. Allowed: {', '.join(sorted(engine.SUPPORTED_EXTENSIONS))}"
        )

    safe_chars = []
    for ch in Path(base).stem:
        if ch in '<>:"/\\|?*\x00' or ord(ch) < 32:
            safe_chars.append("_")
        else:
            safe_chars.append(ch)
    safe_stem = "".join(safe_chars).strip(". ") or "uploaded"
    return f"{safe_stem[:120]}{ext}"


def _clean_local_path(raw_path: str) -> str:
    """Normalize a user-provided local file path and validate extension."""
    cleaned = (raw_path or "").strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ('"', "'"):
        cleaned = cleaned[1:-1].strip()
    if not cleaned:
        raise ValueError("Local file path is required")
    p = Path(cleaned)
    ext = p.suffix.lower()
    if ext not in engine.SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension '{ext}'. Allowed: {', '.join(sorted(engine.SUPPORTED_EXTENSIONS))}"
        )
    if not p.is_file():
        raise FileNotFoundError(f"Input file not found: {p.name}")
    return str(p)


class _UISessionState:
    """Thread-safe per-process state for session token, uploads, and jobs."""

    def __init__(self, session_dir: Path | None = None) -> None:
        self.token: str = secrets.token_urlsafe(32)
        if session_dir is None:
            self.session_dir = Path(tempfile.mkdtemp(prefix="excel_mask_ui_"))
            self._owns_dir = True
        else:
            self.session_dir = session_dir
            self.session_dir.mkdir(parents=True, exist_ok=True)
            self._owns_dir = False

        self.uploads_dir = self.session_dir / "uploads"
        self.outputs_dir = self.session_dir / "outputs"
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.outputs_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self.files: dict[str, dict[str, Any]] = {}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.column_samples: dict[str, dict[str, dict[str, list[Any]]]] = {}
        self._cleaned = False

    def register_upload(self, file_id: str, path: Path, filename: str, size: int) -> None:
        with self._lock:
            self.files[file_id] = {
                "path": str(path),
                "filename": filename,
                "size": size,
            }

    def get_upload(self, file_id: str) -> dict[str, Any] | None:
        with self._lock:
            info = self.files.get(file_id)
            return dict(info) if info else None

    def remove_upload(self, file_id: str) -> dict[str, Any] | None:
        with self._lock:
            info = self.files.pop(file_id, None)
            self.column_samples.pop(f"file:{file_id}", None)
            return dict(info) if info else None

    def set_column_samples(
        self,
        source_key: str,
        samples_by_sheet: dict[str, dict[str, list[Any]]],
        *,
        replace: bool = True,
    ) -> None:
        copied = {
            sname: {cname: list(vals) for cname, vals in cols.items()}
            for sname, cols in samples_by_sheet.items()
        }
        with self._lock:
            if replace or source_key not in self.column_samples:
                self.column_samples[source_key] = copied
            else:
                self.column_samples[source_key].update(copied)

    def get_column_samples(
        self,
        source_key: str,
        sheet_name: str | None = None,
    ) -> dict[str, dict[str, list[Any]]] | None:
        with self._lock:
            sheets = self.column_samples.get(source_key)
            if sheets is None:
                return None
            if sheet_name is not None:
                cols = sheets.get(sheet_name)
                if cols is None:
                    return None
                return {sheet_name: {cname: list(vals) for cname, vals in cols.items()}}
            return {
                sname: {cname: list(vals) for cname, vals in cols.items()}
                for sname, cols in sheets.items()
            }

    def clear_column_samples(self, source_key: str | None = None) -> None:
        with self._lock:
            if source_key is None:
                self.column_samples.clear()
            else:
                self.column_samples.pop(source_key, None)

    def register_job(self, job_id: str, output_path: Path, filename: str) -> None:
        with self._lock:
            self.jobs[job_id] = {
                "output_path": str(output_path),
                "filename": filename,
            }

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            info = self.jobs.get(job_id)
            return dict(info) if info else None

    def cleanup(self) -> None:
        with self._lock:
            if self._cleaned:
                return
            self._cleaned = True
            self.column_samples.clear()
            if self._owns_dir and self.session_dir.exists():
                shutil.rmtree(self.session_dir, ignore_errors=True)


def _render_html(token: str) -> str:
    """Return self-contained offline Chinese Web UI HTML with injected CSRF token."""
    token_json = json.dumps(token)
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Excel / CSV 本地离线数据脱敏向导</title>
<style>
  :root {
    --bg: #f4f6fb;
    --card: #ffffff;
    --surface: #f8fafc;
    --text: #0f172a;
    --text-2: #334155;
    --muted: #64748b;
    --border: #e2e8f0;
    --border-strong: #cbd5e1;
    --primary: #2563eb;
    --primary-hover: #1d4ed8;
    --primary-soft: #eff6ff;
    --success: #059669;
    --success-text: #065f46;
    --success-bg: #dcfce7;
    --success-soft: #ecfdf5;
    --success-border: #a7f3d0;
    --warn: #b45309;
    --warn-bg: #fffbeb;
    --warn-border: #fde68a;
    --danger: #dc2626;
    --danger-bg: #fef2f2;
    --danger-border: #fecaca;
    --shadow-card: 0 10px 30px rgba(15, 23, 42, 0.06), 0 1px 3px rgba(15, 23, 42, 0.04);
    --shadow-pill: 0 2px 10px rgba(15, 23, 42, 0.05);
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    padding: 0;
    min-height: 100%;
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  .hidden { display: none !important; }
  .mono { font-family: var(--mono); }
  .hint { font-size: 12px; color: var(--muted); }

  .wizard-shell {
    max-width: 1120px;
    margin: 0 auto;
    padding: 26px 22px 56px;
  }

  /* Top Source File Capsule */
  .capsule-wrap {
    display: flex;
    justify-content: center;
    margin-bottom: 18px;
    min-height: 38px;
  }
  .source-capsule {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 7px 18px;
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 999px;
    box-shadow: var(--shadow-pill);
    font-size: 13px;
    color: var(--text-2);
    max-width: 100%;
  }
  .capsule-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--success);
    flex-shrink: 0;
  }
  .capsule-name {
    font-weight: 600;
    color: var(--text);
    max-width: 340px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .capsule-sep {
    color: #cbd5e1;
    user-select: none;
  }
  .capsule-meta {
    color: var(--muted);
    white-space: nowrap;
  }
  .capsule-action {
    border: none;
    background: none;
    padding: 0;
    margin: 0;
    font: inherit;
    font-weight: 600;
    color: var(--primary);
    cursor: pointer;
    white-space: nowrap;
  }
  .capsule-action:hover:not(:disabled) {
    text-decoration: underline;
    color: var(--primary-hover);
  }
  .capsule-action:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }

  /* Horizontal 4-Step Stepper */
  .stepper {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0;
    margin: 0 auto 24px;
    max-width: 820px;
    padding: 0 8px;
  }
  .step-item {
    display: inline-flex;
    align-items: center;
    gap: 9px;
    white-space: nowrap;
    cursor: default;
    user-select: none;
    transition: opacity 0.15s;
  }
  .step-item.is-clickable {
    cursor: pointer;
  }
  .step-item.is-clickable:hover .step-label {
    color: var(--primary);
  }
  .step-circle {
    width: 26px;
    height: 26px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    font-weight: 700;
    flex-shrink: 0;
    transition: all 0.2s ease;
    background: #cbd5e1;
    color: #ffffff;
  }
  .step-label {
    font-size: 14px;
    font-weight: 500;
    color: var(--muted);
    transition: color 0.2s ease;
  }
  .step-item.is-done .step-circle {
    background: #bbf7d0;
    color: var(--success-text);
  }
  .step-item.is-done .step-label {
    color: var(--text-2);
    font-weight: 600;
  }
  .step-item.is-active .step-circle {
    background: var(--primary);
    color: #ffffff;
    box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.14);
  }
  .step-item.is-active .step-label {
    color: var(--text);
    font-weight: 700;
  }
  .step-line {
    flex: 1 1 48px;
    height: 2px;
    min-width: 22px;
    max-width: 86px;
    margin: 0 14px;
    background: #dbe2ea;
    border-radius: 2px;
    transition: background 0.2s ease;
  }
  .step-line.is-done {
    background: var(--primary);
  }

  /* Main Workspace Card */
  .workspace-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    box-shadow: var(--shadow-card);
    overflow: visible;
  }
  .card-header {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: 14px;
    padding: 26px 30px 18px;
  }
  .card-title-group h1,
  .card-title-group h2 {
    margin: 0;
    font-size: 21px;
    font-weight: 700;
    letter-spacing: -0.01em;
    color: var(--text);
  }
  .card-subtitle {
    margin: 5px 0 0;
    font-size: 13.5px;
    color: var(--muted);
  }
  .security-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 13px;
    border-radius: 999px;
    font-size: 12.5px;
    font-weight: 600;
    background: var(--success-soft);
    color: var(--success);
    border: 1px solid var(--success-border);
    white-space: nowrap;
  }
  .card-body {
    padding: 0 30px 26px;
  }

  /* Mode Switcher */
  .mode-switch {
    display: inline-flex;
    padding: 4px;
    background: #f1f5f9;
    border: 1px solid var(--border);
    border-radius: 9px;
    gap: 4px;
    margin-bottom: 18px;
  }
  .tab-btn {
    padding: 7px 16px;
    border: none;
    background: transparent;
    color: var(--muted);
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 600;
    font-family: inherit;
    transition: all 0.15s ease;
  }
  .tab-btn:hover {
    color: var(--text);
  }
  .tab-btn.active {
    background: #ffffff;
    color: var(--primary);
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
  }

  /* Dropzone */
  .dropzone {
    border: 2px dashed var(--border-strong);
    border-radius: 10px;
    padding: 44px 24px;
    text-align: center;
    background: var(--surface);
    cursor: pointer;
    transition: border-color 0.18s, background 0.18s, box-shadow 0.18s;
  }
  .dropzone:hover {
    border-color: #93c5fd;
    background: #f8fbff;
  }
  .dropzone.dragover {
    border-color: var(--primary);
    background: var(--primary-soft);
    box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.08);
  }
  .dropzone.has-file {
    border-style: solid;
    border-color: var(--success-border);
    background: #f8fffb;
    cursor: default;
    padding: 20px 22px;
    text-align: left;
  }
  .dropzone-icon {
    width: 44px;
    height: 44px;
    margin: 0 auto 12px;
    border-radius: 12px;
    background: #eff6ff;
    color: var(--primary);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .dropzone-title {
    font-size: 15px;
    font-weight: 600;
    color: var(--text);
  }
  .dropzone-title span {
    color: var(--primary);
  }
  .dropzone p {
    margin: 6px 0 0;
    color: var(--muted);
    font-size: 12.5px;
  }

  .uploaded-card {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
  }
  .uploaded-card-info {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }
  .uploaded-file-name {
    font-weight: 700;
    font-size: 14.5px;
    color: var(--text);
    word-break: break-all;
  }
  .uploaded-file-size {
    font-size: 12.5px;
    color: var(--muted);
  }

  .path-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 22px;
  }
  .path-label {
    display: block;
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 8px;
  }
  .trust-strip {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 16px;
  }
  .trust-item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 11px;
    border-radius: 6px;
    background: var(--surface);
    border: 1px solid var(--border);
    font-size: 12px;
    color: var(--muted);
  }
  .trust-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--success);
  }

  /* Form controls & Buttons */
  input[type="text"], input[type="number"], select {
    padding: 8px 11px;
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    font-size: 13px;
    font-family: inherit;
    color: var(--text);
    background: #ffffff;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  input[type="text"]:focus, input[type="number"]:focus, select:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14);
  }
  .input-full {
    width: 100%;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
  }
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 9px 18px;
    border-radius: 8px;
    border: 1px solid transparent;
    font-size: 13.5px;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
    transition: background 0.15s, border-color 0.15s, transform 0.05s;
    white-space: nowrap;
  }
  .btn:active:not(:disabled) {
    transform: translateY(0.5px);
  }
  .btn-sm {
    padding: 5px 11px;
    font-size: 12px;
    border-radius: 6px;
  }
  .btn-lg {
    padding: 10px 22px;
    font-size: 14px;
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn-primary {
    background: var(--primary);
    color: #ffffff;
  }
  .btn-primary:hover:not(:disabled) {
    background: var(--primary-hover);
  }
  .btn-success {
    background: var(--success);
    color: #ffffff;
  }
  .btn-success:hover:not(:disabled) {
    background: #047857;
  }
  .btn-secondary {
    background: #ffffff;
    color: var(--text-2);
    border-color: var(--border-strong);
  }
  .btn-secondary:hover:not(:disabled) {
    background: var(--surface);
    border-color: #94a3b8;
  }
  .btn-ghost {
    background: var(--surface);
    color: var(--text-2);
    border-color: var(--border);
  }
  .btn-ghost:hover:not(:disabled) {
    background: #f1f5f9;
  }
  .btn-danger-outline {
    background: #ffffff;
    color: var(--danger);
    border-color: #fca5a5;
  }
  .btn-danger-outline:hover:not(:disabled) {
    background: var(--danger-bg);
    border-color: var(--danger);
  }

  /* Status Alert */
  .status-box {
    margin-top: 14px;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
    display: none;
  }
  .status-box.show { display: block; }
  .status-info { background: var(--primary-soft); color: #1e40af; border: 1px solid #bfdbfe; }
  .status-ok { background: var(--success-soft); color: var(--success-text); border: 1px solid var(--success-border); }
  .status-err { background: var(--danger-bg); color: #991b1b; border: 1px solid var(--danger-border); }

  /* Step 2 Top Meta + Advanced Settings Bar */
  .step2-meta-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding-bottom: 14px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 14px;
  }
  .step2-toolbar-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .meta-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 14px;
    font-size: 12.5px;
    color: var(--muted);
  }
  .meta-bar strong {
    color: var(--text);
    font-weight: 600;
  }
  .guide-toggle-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-radius: 7px;
    border: 1px solid #bfdbfe;
    background: var(--primary-soft);
    color: var(--primary);
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
    transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease;
  }
  .guide-toggle-btn:hover {
    background: #dbeafe;
    border-color: #93c5fd;
  }
  .guide-toggle-btn.is-open {
    background: var(--primary);
    border-color: var(--primary);
    color: #ffffff;
  }
  .guide-panel {
    overflow: hidden;
    max-height: 0;
    opacity: 0;
    transform: translateY(-4px);
    margin-bottom: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    transition: max-height 0.28s ease, opacity 0.2s ease, transform 0.2s ease, margin-bottom 0.2s ease;
  }
  .guide-panel.is-open {
    max-height: 1600px;
    opacity: 1;
    transform: translateY(0);
    margin-bottom: 14px;
  }
  .guide-panel-inner {
    padding: 14px 16px;
  }
  .guide-panel-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 10px;
  }
  .guide-panel-title {
    font-size: 13.5px;
    font-weight: 700;
    color: var(--text);
  }
  .guide-panel-sub {
    font-size: 12px;
    color: var(--muted);
  }
  .guide-table-wrap {
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow-x: auto;
    background: #ffffff;
  }
  .guide-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }
  .guide-table th {
    background: #f8fafc;
    padding: 8px 11px;
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    text-align: left;
    white-space: nowrap;
  }
  .guide-table td {
    padding: 9px 11px;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: top;
    line-height: 1.5;
    color: var(--text-2);
  }
  .guide-table tbody tr:last-child td {
    border-bottom: none;
  }
  .guide-rule-name {
    font-weight: 600;
    color: var(--text);
    white-space: nowrap;
  }
  .guide-rule-tag {
    display: inline-block;
    margin-top: 3px;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-family: var(--mono);
    background: #f1f5f9;
    color: var(--muted);
    border: 1px solid var(--border);
  }
  .guide-ex-code {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 11.5px;
    background: #f1f5f9;
    color: var(--text);
    border: 1px solid #e2e8f0;
  }
  .guide-ex-after {
    background: #ecfdf5;
    color: #065f46;
    border-color: #a7f3d0;
  }
  .guide-warn-note {
    margin-top: 5px;
    padding: 5px 8px;
    border-radius: 6px;
    background: var(--warn-bg);
    border: 1px solid var(--warn-border);
    color: #92400e;
    font-size: 12px;
    line-height: 1.45;
  }
  .guide-regex-list {
    margin: 5px 0 0;
    padding: 0;
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .guide-regex-item {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 5px;
    font-size: 12px;
  }
  .guide-copy-code {
    display: inline-flex;
    align-items: center;
    padding: 1px 6px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 11.5px;
    background: #eff6ff;
    color: #1e40af;
    border: 1px solid #bfdbfe;
    cursor: pointer;
    user-select: all;
  }
  .guide-copy-code:hover {
    background: #dbeafe;
  }
  .guide-copy-code.is-copied {
    background: #dcfce7;
    color: #065f46;
    border-color: #86efac;
  }
  .adv-toggle-btn {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 6px 12px;
    border-radius: 7px;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text-2);
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
  }
  .adv-toggle-btn:hover {
    background: #f1f5f9;
    border-color: var(--border-strong);
  }
  .adv-toggle-btn.is-open {
    background: var(--primary-soft);
    border-color: #bfdbfe;
    color: var(--primary);
  }
  .adv-panel {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    align-items: flex-end;
    padding: 14px 16px;
    margin-bottom: 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    font-size: 12px;
    color: var(--muted);
  }
  .field label {
    font-weight: 600;
    color: var(--text-2);
  }

  /* Sheet Tabs */
  .sheet-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-bottom: 12px;
  }
  .sheet-tab-btn {
    padding: 6px 13px;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text-2);
    border-radius: 7px;
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
  }
  .sheet-tab-btn.active {
    background: var(--primary-soft);
    color: var(--primary);
    border-color: #93c5fd;
  }

  /* Compact Batch Toolbar */
  .batch-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 9px 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 9px;
    margin-bottom: 12px;
  }
  .batch-select-group, .batch-action-group {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .batch-count {
    font-size: 12.5px;
    color: var(--muted);
    padding: 4px 9px;
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .batch-count strong {
    color: var(--primary);
  }
  #batchRuleSelect {
    padding: 5px 10px;
    font-size: 12.5px;
    border-radius: 6px;
  }

  /* Flatfile Mapping Table */
  .table-wrap {
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow-x: auto;
    background: #ffffff;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13.5px;
  }
  th {
    background: var(--surface);
    padding: 11px 14px;
    text-align: left;
    font-size: 12.5px;
    font-weight: 600;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td {
    padding: 13px 14px;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: middle;
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  tbody tr {
    transition: background 0.12s ease;
  }
  tbody tr:hover {
    background: #fafcff;
  }
  tr.row-selected {
    background: #eff6ff !important;
  }
  tr.row-disabled-rule td.col-source-cell {
    opacity: 0.72;
  }

  .source-main {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .col-name-text {
    font-weight: 600;
    color: var(--text);
    font-size: 14px;
  }
  .kind-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 5px;
    font-size: 11.5px;
    font-weight: 600;
    background: #f1f5f9;
    color: var(--muted);
    border: 1px solid var(--border);
    white-space: nowrap;
  }
  .tag {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: 5px;
    font-size: 11.5px;
    font-weight: 600;
    white-space: nowrap;
  }
  .tag-ready {
    background: var(--success-soft);
    color: var(--success);
    border: 1px solid var(--success-border);
  }
  .tag-sens {
    background: #fef2f2;
    color: #b91c1c;
    border: 1px solid #fecaca;
  }
  .tag-inline {
    background: var(--warn-bg);
    color: var(--warn);
    border: 1px solid var(--warn-border);
  }
  .source-sub {
    margin-top: 4px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    color: var(--muted);
  }
  .arrow-cell {
    width: 34px;
    text-align: center;
    color: #94a3b8;
    font-size: 16px;
    padding-left: 4px;
    padding-right: 4px;
    user-select: none;
  }

  /* Rule selector + lightweight parameter popover/drawer */
  .rule-cell {
    min-width: 280px;
  }
  .rule-control-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .rule-select {
    flex: 1 1 auto;
    min-width: 210px;
    max-width: 300px;
    height: 36px;
    padding: 6px 10px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 500;
    background: #ffffff;
    color: var(--text);
  }
  .rule-select.is-none {
    background: var(--surface);
    color: var(--muted);
    border-color: var(--border);
  }
  .btn-param-toggle {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 34px;
    padding: 0 10px;
    border-radius: 7px;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--muted);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
    white-space: nowrap;
  }
  .btn-param-toggle:hover {
    background: #f1f5f9;
    color: var(--text);
    border-color: var(--border-strong);
  }
  .btn-param-toggle.is-open,
  .btn-param-toggle.has-custom {
    background: var(--primary-soft);
    border-color: #bfdbfe;
    color: var(--primary);
  }
  .inline-params-drawer {
    margin-top: 8px;
    padding: 10px 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .rule-inline-hint {
    margin-top: 5px;
    font-size: 11.5px;
    line-height: 1.4;
    color: var(--muted);
  }
  .param-hint {
    margin-top: 7px;
    padding-top: 6px;
    border-top: 1px dashed var(--border);
    font-size: 11.5px;
    line-height: 1.4;
    color: var(--muted);
  }
  .param-box {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }
  .param-field {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .param-field span {
    font-size: 11px;
    color: var(--muted);
    font-weight: 600;
  }
  .param-mini {
    width: 104px !important;
    padding: 5px 8px !important;
    font-size: 12px !important;
    border-radius: 6px !important;
  }
  .param-med {
    width: 152px !important;
    padding: 5px 8px !important;
    font-size: 12px !important;
    border-radius: 6px !important;
  }
  .param-wide {
    width: auto !important;
    min-width: 220px !important;
    padding: 5px 8px !important;
    font-size: 12px !important;
    border-radius: 6px !important;
  }

  /* Preview Pills */
  .preview-cell {
    min-width: 190px;
  }
  .preview-stack {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
  }
  .preview-pill {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 12.5px;
    font-weight: 600;
    line-height: 1.4;
    max-width: 240px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .preview-pill-masked {
    background: #dcfce7;
    color: #065f46;
    border: 1px solid #bbf7d0;
    font-family: var(--mono);
  }
  .preview-pill-raw {
    background: #f1f5f9;
    color: #475569;
    border: 1px solid #e2e8f0;
    font-family: var(--mono);
    font-weight: 500;
  }
  .preview-origin-tag {
    display: inline-block;
    padding: 2px 6px;
    border-radius: 5px;
    font-size: 11px;
    font-weight: 600;
    background: #e2e8f0;
    color: #475569;
    white-space: nowrap;
  }
  .preview-pill-error {
    background: var(--warn-bg);
    color: var(--warn);
    border: 1px solid var(--warn-border);
    font-weight: 600;
    border-radius: 8px;
    white-space: normal;
    max-width: 280px;
  }
  .preview-pill-muted {
    background: #eef2f6;
    color: #64748b;
    font-weight: 500;
  }
  .preview-unchanged-wrap {
    display: flex;
    flex-direction: column;
    gap: 5px;
    align-items: flex-start;
  }
  .preview-unchanged-note {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 11.5px;
    font-weight: 600;
    background: var(--warn-bg);
    color: var(--warn);
    border: 1px solid var(--warn-border);
    line-height: 1.35;
  }
  .preview-pill-unchanged {
    background: #fef3c7;
    color: #92400e;
    border: 1px solid #fcd34d;
    font-family: var(--mono);
    font-weight: 600;
  }

  /* Sticky Wizard Footer */
  .wizard-footer {
    position: sticky;
    bottom: 0;
    z-index: 10;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    padding: 16px 30px;
    background: rgba(255, 255, 255, 0.96);
    backdrop-filter: blur(6px);
    border-top: 1px solid var(--border);
    border-radius: 0 0 12px 12px;
  }
  .footer-stats {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    font-size: 13.5px;
    color: var(--text-2);
  }
  .footer-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #93c5fd;
    display: inline-block;
  }
  .footer-actions {
    display: inline-flex;
    align-items: center;
    gap: 10px;
  }

  /* Step 3 Processing View */
  .progress-stage {
    padding: 58px 30px 64px;
    text-align: center;
  }
  .spinner-ring {
    width: 54px;
    height: 54px;
    margin: 0 auto 20px;
    border-radius: 50%;
    border: 4px solid #dbeafe;
    border-top-color: var(--primary);
    animation: wizard-spin 0.9s linear infinite;
  }
  @keyframes wizard-spin {
    to { transform: rotate(360deg); }
  }
  .progress-title {
    margin: 0 0 8px;
    font-size: 20px;
    font-weight: 700;
    color: var(--text);
  }
  .progress-desc {
    margin: 0 auto 22px;
    max-width: 480px;
    font-size: 13.5px;
    color: var(--muted);
  }
  .progress-bar-track {
    width: 100%;
    max-width: 420px;
    height: 8px;
    margin: 0 auto 20px;
    background: #e2e8f0;
    border-radius: 999px;
    overflow: hidden;
  }
  .progress-bar-fill {
    width: 42%;
    height: 100%;
    background: linear-gradient(90deg, #3b82f6, #2563eb);
    border-radius: 999px;
    animation: wizard-indeterminate 1.4s ease-in-out infinite;
  }
  @keyframes wizard-indeterminate {
    0% { transform: translateX(-110%); }
    100% { transform: translateX(260%); }
  }
  .progress-pills {
    display: inline-flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 8px;
  }

  /* Step 4 KPIs & Summary */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 18px;
  }
  .stat-item {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 13px 15px;
  }
  .stat-item .k {
    font-size: 12px;
    color: var(--muted);
  }
  .stat-item .v {
    font-size: 19px;
    font-weight: 700;
    color: var(--text);
    margin-top: 3px;
  }
  .result-rule-pill {
    display: inline-block;
    margin: 2px 4px 2px 0;
    padding: 3px 9px;
    border-radius: 6px;
    font-size: 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-2);
  }

  @media (max-width: 720px) {
    .wizard-shell { padding: 16px 12px 40px; }
    .card-header { padding: 20px 18px 14px; }
    .card-body { padding: 0 18px 20px; }
    .wizard-footer { padding: 14px 18px; }
    .stepper { gap: 0; overflow-x: auto; justify-content: flex-start; }
    .step-line { min-width: 14px; margin: 0 8px; }
    .step-label { font-size: 12.5px; }
  }
</style>
</head>
<body>
<div class="wizard-shell">
  <!-- Top Source File Capsule (shown on Steps 2-4) -->
  <div class="capsule-wrap">
    <div id="sourceCapsule" class="source-capsule hidden">
      <span class="capsule-icon" aria-hidden="true">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
          <polyline points="14 2 14 8 20 8"></polyline>
          <line x1="8" y1="13" x2="16" y2="13"></line>
          <line x1="8" y1="17" x2="16" y2="17"></line>
        </svg>
      </span>
      <span id="capsuleFileName" class="capsule-name"></span>
      <span class="capsule-sep">·</span>
      <span id="capsuleFileMeta" class="capsule-meta"></span>
      <span class="capsule-sep">·</span>
      <button type="button" id="capsuleReuploadBtn" class="capsule-action">重新上传</button>
    </div>
  </div>

  <!-- Horizontal 4-Step Wizard Stepper -->
  <nav class="stepper" id="wizardStepper" aria-label="脱敏步骤">
    <div class="step-item is-active" data-step="1" id="stepperStep1">
      <span class="step-circle" id="stepCircle1">1</span>
      <span class="step-label">1. 上传文件</span>
    </div>
    <div class="step-line" id="stepLine1"></div>
    <div class="step-item" data-step="2" id="stepperStep2">
      <span class="step-circle" id="stepCircle2">2</span>
      <span class="step-label">2. 确认脱敏规则</span>
    </div>
    <div class="step-line" id="stepLine2"></div>
    <div class="step-item" data-step="3" id="stepperStep3">
      <span class="step-circle" id="stepCircle3">3</span>
      <span class="step-label">3. 执行清洗</span>
    </div>
    <div class="step-line" id="stepLine3"></div>
    <div class="step-item" data-step="4" id="stepperStep4">
      <span class="step-circle" id="stepCircle4">4</span>
      <span class="step-label">4. 下载结果</span>
    </div>
  </nav>

  <!-- Main Centered Workspace Card (Single Step Focus) -->
  <main class="workspace-card">
    <!-- Step 1: Upload / Local Path -->
    <section id="step1Card">
      <div class="card-header">
        <div class="card-title-group">
          <h1>上传待脱敏数据文件</h1>
          <p class="card-subtitle">支持 .xlsx / .xlsm / .xls / .xlsb / .csv，全量扫描与脱敏均在本机 127.0.0.1 离线完成</p>
        </div>
        <div class="security-badge">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <polyline points="9 12 11 14 15 10"></polyline>
          </svg>
          <span>本地离线安全处理</span>
        </div>
      </div>

      <div class="card-body">
        <div class="mode-switch">
          <button type="button" class="tab-btn active" id="tabUploadBtn">拖拽 / 选择文件上传</button>
          <button type="button" class="tab-btn" id="tabPathBtn">输入本机文件路径（超大表免拷贝）</button>
        </div>

        <div id="panelUpload">
          <div class="dropzone" id="dropzone">
            <input type="file" id="fileInput" accept=".xlsx,.xlsm,.xls,.xlsb,.csv" class="hidden">
            <div id="dropzoneEmpty">
              <div class="dropzone-icon" aria-hidden="true">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                  <polyline points="17 8 12 3 7 8"></polyline>
                  <line x1="12" y1="3" x2="12" y2="15"></line>
                </svg>
              </div>
              <div class="dropzone-title"><span>点击选择文件</span> 或将 Excel / CSV 拖拽到此区域</div>
              <p>文件通过本地二进制流直传 127.0.0.1 会话临时目录，服务退出后自动清理</p>
            </div>
            <div id="uploadedFileCard" class="uploaded-card hidden">
              <div class="uploaded-card-info">
                <span class="tag tag-ready">已就绪</span>
                <span id="uploadedFileName" class="uploaded-file-name mono"></span>
                <span id="uploadedFileSize" class="uploaded-file-size"></span>
                <span class="hint">可点击右下角“本地全量识别 →”开始扫描</span>
              </div>
              <button type="button" class="btn btn-danger-outline btn-sm" id="clearUploadBtn">删除 / 重新上传</button>
            </div>
          </div>
        </div>

        <div id="panelPath" class="hidden">
          <div class="path-box">
            <label for="localPathInput" class="path-label">本机文件完整路径</label>
            <input type="text" id="localPathInput" class="input-full mono"
                   placeholder="例如：/Users/name/data/customers.xlsx 或 C:\\data\\customers.xlsx">
            <div class="hint" style="margin-top:8px;">
              直接流式读取本地路径，输出将保存至同目录 <span class="mono">&lt;原文件名&gt;_masked.xlsx</span>（或 <span class="mono">.csv</span>），绝不覆盖原文件。
            </div>
          </div>
        </div>

        <div class="trust-strip">
          <span class="trust-item"><span class="trust-dot"></span>127.0.0.1 仅本机回环</span>
          <span class="trust-item"><span class="trust-dot"></span>100% 纯离线零外网请求</span>
          <span class="trust-item"><span class="trust-dot"></span>原始明文不入模型上下文</span>
        </div>

        <div id="step1Status" class="status-box"></div>
      </div>

      <div class="wizard-footer">
        <div class="footer-stats">
          <span id="inspectMeta" class="hint">支持单表或多工作表全量扫描</span>
        </div>
        <div class="footer-actions">
          <button type="button" class="btn btn-secondary hidden" id="resumeStep2Btn">返回已识别规则</button>
          <button type="button" class="btn btn-primary" id="inspectBtn">本地全量识别 →</button>
        </div>
      </div>
    </section>

    <!-- Step 2: Configure Masking Rules (Flatfile Mapping Style) -->
    <section id="step2Card" class="hidden">
      <div class="card-header">
        <div class="card-title-group">
          <h2>配置字段脱敏规则</h2>
          <p class="card-subtitle">系统已自动识别敏感列，请确认每列的脱敏方式</p>
        </div>
        <div class="security-badge">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <polyline points="9 12 11 14 15 10"></polyline>
          </svg>
          <span>本地离线安全处理</span>
        </div>
      </div>

      <div class="card-body">
        <div class="step2-meta-row">
          <div class="meta-bar" id="fileMetaBar"></div>
          <div class="step2-toolbar-actions">
            <button type="button" class="guide-toggle-btn" id="ruleGuideToggleBtn" aria-expanded="false" aria-controls="ruleGuidePanel">
              <span>📖 规则说明与示例</span>
            </button>
            <button type="button" class="adv-toggle-btn" id="advToggleBtn" aria-expanded="false">
              <span>⚙ 高级加密与并发设置</span>
              <span id="advSummaryTag" class="hint">线程 默认 8</span>
            </button>
          </div>
        </div>

        <div id="ruleGuidePanel" class="guide-panel hidden" aria-hidden="true">
          <div class="guide-panel-inner">
            <div class="guide-panel-head">
              <div class="guide-panel-title">📖 8 种脱敏规则对照说明与示例</div>
              <div class="guide-panel-sub">切换任意列规则后，右侧「脱敏效果预览」会实时刷新；若显示琥珀色「未命中规则」，请换用其他规则或调整参数</div>
            </div>
            <div class="guide-table-wrap">
              <table class="guide-table">
                <thead>
                  <tr>
                    <th style="width:185px;">规则名称</th>
                    <th style="width:230px;">适用场景（适合什么数据）</th>
                    <th style="width:235px;">脱敏前 → 脱敏后示例</th>
                    <th>参数用法提示</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <div class="guide-rule-name">星号遮挡（保留首尾）</div>
                      <span class="guide-rule-tag">mask_keep</span>
                    </td>
                    <td>手机号、身份证、银行卡、邮箱、人员姓名、公司名称、地址、业务编码等需保留局部识别特征的整格数据。</td>
                    <td>
                      <span class="guide-ex-code">13812345678</span> → <span class="guide-ex-code guide-ex-after">138****5678</span><br>
                      <span class="guide-ex-code">张三丰</span> → <span class="guide-ex-code guide-ex-after">张**</span><br>
                      <span class="guide-ex-code">某科技有限公司</span> → <span class="guide-ex-code guide-ex-after">某科****司</span>
                    </td>
                    <td>点击「⚙ 参数」可自定义「保留前几位」「保留后几位」和「遮挡符号」（默认 <span class="guide-ex-code">*</span>）；全部留空则按识别类型自动遮挡。</td>
                  </tr>
                  <tr>
                    <td>
                      <div class="guide-rule-name">加密代号替换（同名同码）</div>
                      <span class="guide-rule-tag">hash_sha256</span>
                    </td>
                    <td>姓名、工号、客户编码、公司名称等需要隐藏原文，且要跨表关联或统计去重的字段（不可逆）。</td>
                    <td>
                      <span class="guide-ex-code">张三</span> → <span class="guide-ex-code guide-ex-after">a3f8c2e190b47d12</span><br>
                      <span class="hint">同一原文+同一口令生成相同代号</span>
                    </td>
                    <td>点击「⚙ 参数」可设「列独立口令」「代号长度」（4~64，默认 16）和「代号前缀」（如 <span class="guide-ex-code">H_</span>）；跨表关联请在顶部「⚙ 高级设置」填写统一加密口令。</td>
                  </tr>
                  <tr>
                    <td>
                      <div class="guide-rule-name">整格替换为固定文字</div>
                      <span class="guide-rule-tag">redact</span>
                    </td>
                    <td>密码、密钥、高度敏感备注或无需保留任何特征的整列数据。</td>
                    <td>
                      <span class="guide-ex-code">sk-secret-9821</span> → <span class="guide-ex-code guide-ex-after">[已脱敏]</span>
                    </td>
                    <td>点击「⚙ 参数」可自定义「替换文本」（默认 <span class="guide-ex-code">[已脱敏]</span>）；空单元格保持为空不替换。</td>
                  </tr>
                  <tr>
                    <td>
                      <div class="guide-rule-name">模糊化处理（留年月/划区间/截断）</div>
                      <span class="guide-rule-tag">generalize</span>
                    </td>
                    <td>出生日期、交易时间、薪资/金额数字、长地址或部门名称等需保留统计分布特征的列。</td>
                    <td>
                      <span class="guide-ex-code">2024-05-18</span> → <span class="guide-ex-code guide-ex-after">2024-05</span><br>
                      <span class="guide-ex-code">3850</span> → <span class="guide-ex-code guide-ex-after">[3800, 3900)</span><br>
                      <span class="guide-ex-code">上海市浦东新区…</span> → <span class="guide-ex-code guide-ex-after">上海市浦...</span>
                    </td>
                    <td>点击「⚙ 参数」选择「模糊方式」：<span class="guide-ex-code">日期只留年月/年份</span>、<span class="guide-ex-code">数字按区间归类</span>（填跨度如 <span class="guide-ex-code">1000</span>）、<span class="guide-ex-code">数字四舍五入</span>、<span class="guide-ex-code">文字只留前几字</span>（填字数如 <span class="guide-ex-code">4</span>）。</td>
                  </tr>
                  <tr>
                    <td>
                      <div class="guide-rule-name">按格式局部替换（高级）</div>
                      <span class="guide-rule-tag">regex_replace</span>
                    </td>
                    <td>有固定格式规律的工号、订单号、流水号、复合编码等，只需遮挡其中特定片段。</td>
                    <td>
                      <span class="guide-ex-code">EMP-123456</span> → <span class="guide-ex-code guide-ex-after">EMP-****56</span><br>
                      <span class="guide-ex-code">ABC-001</span> → <span class="guide-ex-code guide-ex-after">***-001</span>
                    </td>
                    <td>
                      <div>点击「⚙ 参数」填写「匹配格式（正则必填）」与「替换为」（默认 <span class="guide-ex-code">***</span>）。<strong>使用 Python 正则语法，分组反向引用请用 <span class="guide-ex-code">\\1</span>、<span class="guide-ex-code">\\2</span>（勿用 <span class="guide-ex-code">$1</span>）。</strong>常见可复制示例（点击代码即可复制）：</div>
                      <ul class="guide-regex-list">
                        <li class="guide-regex-item">
                          <span>提取前缀保留末尾：</span>
                          <code class="guide-copy-code" data-copy="(.*)(-\\w+)$" title="点击复制">(.*)(-\\w+)$</code>
                          <span>替换为</span>
                          <code class="guide-copy-code" data-copy="***\\2" title="点击复制">***\\2</code>
                        </li>
                        <li class="guide-regex-item">
                          <span>手机号遮挡中间 4 位：</span>
                          <code class="guide-copy-code" data-copy="(\\d{3})\\d{4}(\\d{4})" title="点击复制">(\\d{3})\\d{4}(\\d{4})</code>
                          <span>替换为</span>
                          <code class="guide-copy-code" data-copy="\\1****\\2" title="点击复制">\\1****\\2</code>
                        </li>
                        <li class="guide-regex-item">
                          <span>遮挡末尾前 4 位保留后 2 位：</span>
                          <code class="guide-copy-code" data-copy="\\d{4}(?=\\d{2}$)" title="点击复制">\\d{4}(?=\\d{2}$)</code>
                          <span>替换为</span>
                          <code class="guide-copy-code" data-copy="****" title="点击复制">****</code>
                        </li>
                        <li class="guide-regex-item">
                          <span>仅遮挡邮箱 @ 前用户名：</span>
                          <code class="guide-copy-code" data-copy="^[^@]+(?=@)" title="点击复制">^[^@]+(?=@)</code>
                          <span>替换为</span>
                          <code class="guide-copy-code" data-copy="***" title="点击复制">***</code>
                        </li>
                      </ul>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <div class="guide-rule-name">长文本隐私清洗</div>
                      <span class="guide-rule-tag">inline_text</span>
                    </td>
                    <td>工单备注、客服反馈、聊天摘要等自由长文本，保留正常业务文字并清洗夹带的个人隐私。</td>
                    <td>
                      <span class="guide-ex-code">联系13812345678，邮箱a@b.com</span><br>
                      → <span class="guide-ex-code guide-ex-after">联系138****5678，邮箱a***@b.com</span>
                    </td>
                    <td>
                      无需额外参数。
                      <div class="guide-warn-note">⚠️ <strong>重要提示</strong>：本规则仅自动遮挡文本中夹带的<strong>手机号 / 身份证 / 银行卡 / 固话 / 邮箱 / IPv4</strong>；若是<strong>公司名称、人员姓名或业务编码</strong>整格脱敏，请选用「星号遮挡（保留首尾）」或「加密代号替换」。</div>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <div class="guide-rule-name">数据混淆（同长度同格式文本混淆）</div>
                      <span class="guide-rule-tag">obfuscate</span>
                    </td>
                    <td>需保留原有位数、编号结构、中英文及分隔符格式的文本或编码（如账套代码、企业名称、工号等），彻底随机打散关联。</td>
                    <td>
                      <span class="guide-ex-code">1000F100</span> → <span class="guide-ex-code guide-ex-after">7482K915</span><br>
                      <span class="guide-ex-code">中国宝武-单体</span> → <span class="guide-ex-code guide-ex-after">华盛瑞泰-云达</span>
                    </td>
                    <td>默认全串按格式随机混淆；可设保留前/后几位（如保留后3位“-单体”），或切为同名同混淆。</td>
                  </tr>
                  <tr>
                    <td>
                      <div class="guide-rule-name">不脱敏（原样保留）</div>
                      <span class="guide-rule-tag">none</span>
                    </td>
                    <td>序号、状态标识、普通分类等无需脱敏的公开字段。</td>
                    <td>
                      <span class="guide-ex-code">已完成</span> → <span class="guide-ex-code">已完成</span>
                    </td>
                    <td>无需参数，该列按原样导出，预览区显示灰色「原样」标记。</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div id="advSettingsPanel" class="adv-panel hidden">
          <div class="field" style="flex:1 1 320px;">
            <label for="globalSaltInput">统一加密口令（用于“加密代号替换”跨表关联）</label>
            <div class="row" style="gap:8px;">
              <input type="text" id="globalSaltInput" class="mono" style="flex:1; min-width:200px;"
                     placeholder="留空则在存在加密代号列时自动生成本次临时口令">
              <button type="button" class="btn btn-secondary btn-sm" id="genSaltBtn">随机生成口令</button>
            </div>
          </div>
          <div class="field">
            <label for="workersInput">并发加速线程（默认 8）</label>
            <input type="number" id="workersInput" min="1" max="60" placeholder="默认 8" style="width:120px;">
          </div>
        </div>

        <div class="sheet-tabs hidden" id="sheetTabs"></div>

        <div class="batch-bar">
          <div class="batch-select-group">
            <span class="hint" style="font-weight:600;color:var(--text-2);">快捷选择：</span>
            <button type="button" class="btn btn-ghost btn-sm" id="selectAllBtn">全选</button>
            <button type="button" class="btn btn-ghost btn-sm" id="selectSensitiveBtn">仅选敏感列</button>
            <button type="button" class="btn btn-ghost btn-sm" id="selectInlineBtn">敏感+内嵌</button>
            <button type="button" class="btn btn-ghost btn-sm" id="invertSelectBtn">反选</button>
            <button type="button" class="btn btn-ghost btn-sm" id="unselectAllBtn">取消选择</button>
          </div>
          <div class="batch-action-group" id="batchToolbar">
            <span class="batch-count">已选 <strong id="selectedCount">0</strong> 列</span>
            <select id="batchRuleSelect" aria-label="批量规则选择"></select>
            <button type="button" class="btn btn-primary btn-sm" id="batchApplyBtn" disabled>应用到所选列</button>
            <button type="button" class="btn btn-secondary btn-sm" id="batchDisableBtn" disabled>设为不脱敏</button>
          </div>
        </div>

        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width:44px;text-align:center;">
                  <input type="checkbox" id="selectAllChk" title="全选 / 取消全选（支持按住 Shift 键范围连选）">
                </th>
                <th>源数据字段</th>
                <th class="arrow-cell" aria-hidden="true"></th>
                <th>脱敏规则</th>
                <th>脱敏效果预览</th>
              </tr>
            </thead>
            <tbody id="columnsTbody"></tbody>
          </table>
        </div>

        <div id="step2Status" class="status-box"></div>
      </div>

      <div class="wizard-footer">
        <div class="footer-stats">
          <span class="footer-dot" aria-hidden="true"></span>
          <span>已启用脱敏 <strong id="enabledMaskCount">0</strong> 列</span>
          <span class="hint" id="footerSelectionHint"></span>
        </div>
        <div class="footer-actions">
          <button type="button" class="btn btn-secondary" id="backToStep1Btn">上一步</button>
          <button type="button" class="btn btn-primary" id="applyBtn">下一步：开始脱敏 →</button>
        </div>
      </div>
    </section>

    <!-- Step 3: Processing View -->
    <section id="step3Progress" class="hidden">
      <div class="progress-stage">
        <div class="spinner-ring" aria-hidden="true"></div>
        <h2 class="progress-title">正在执行本地高并发流式清洗…</h2>
        <p class="progress-desc">正在本机多进程执行字段脱敏与格式写出，原始明文全程不离开本机、不进入外部模型，请稍候。</p>
        <div class="progress-bar-track" aria-hidden="true">
          <div class="progress-bar-fill"></div>
        </div>
        <div class="progress-pills" id="progressMetaPills"></div>
      </div>
    </section>

    <!-- Step 4: Completed & Download -->
    <section id="step4Card" class="hidden">
      <div class="card-header">
        <div class="card-title-group">
          <h2>脱敏完成，下载结果</h2>
          <p class="card-subtitle">已完成全量数据流式脱敏与统计核验，可直接导出脱敏文件</p>
        </div>
        <div class="security-badge">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <polyline points="9 12 11 14 15 10"></polyline>
          </svg>
          <span>本地离线安全处理</span>
        </div>
      </div>

      <div class="card-body">
        <div class="stats-grid" id="resultStats"></div>
        <div id="outputPathNotice" class="status-box status-ok" style="margin-bottom:16px;"></div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>工作表</th>
                <th>总行数</th>
                <th>数据行数</th>
                <th>脱敏列及命中数</th>
              </tr>
            </thead>
            <tbody id="resultSheetsTbody"></tbody>
          </table>
        </div>
      </div>

      <div class="wizard-footer">
        <div class="footer-actions">
          <button type="button" class="btn btn-secondary" id="backToStep2Btn">← 返回修改规则</button>
          <button type="button" class="btn btn-secondary" id="newFileBtn">脱敏新文件</button>
        </div>
        <div class="footer-actions">
          <button type="button" class="btn btn-success btn-lg" id="downloadBtn">下载脱敏文件</button>
        </div>
      </div>
    </section>
  </main>
</div>

<script>
(function() {
  const TOKEN = __TOKEN__;
  const RULES = [
    {
      value: "mask_keep",
      label: "星号遮挡（保留首尾）",
      desc: "保留开头和结尾的几个字或数字，中间用 * 遮挡（如 138****5678、张*）",
      shortHint: "保留首尾字符中间打 *；点「⚙ 参数」可自定义保留位数与符号",
      paramHint: "保留前/后几位留空时，将按已识别的敏感类型自动遮挡（未知类型默认留首2尾2）。",
      hasParams: true
    },
    {
      value: "hash_sha256",
      label: "加密代号替换（同名同码）",
      desc: "把内容变成固定长度的加密代号；相同原文会变成相同代号，方便跨表关联或去重统计，且无法反推原文",
      shortHint: "转为不可逆加密代号（同名同码）；可在顶部「⚙ 高级设置」设统一口令跨表关联",
      paramHint: "列独立口令留空时自动沿用顶部「统一加密口令」；相同原文与口令始终生成相同代号。",
      hasParams: true
    },
    {
      value: "redact",
      label: "整格替换为固定文字",
      desc: "把整列有内容的地方全部替换成同一句文字（默认 [已脱敏]），完全隐藏原信息",
      shortHint: "整格替换为固定文字（默认 [已脱敏]）；点「⚙ 参数」可自定义替换文案",
      paramHint: "所有非空单元格均替换为同一固定文本，空单元格保持为空。",
      hasParams: true
    },
    {
      value: "generalize",
      label: "模糊化处理（留年月/划区间/截断）",
      desc: "降低精确度保护隐私但保留统计特征（如日期只留年月/年份、数字按区间归类/取整、文字只留前几字）",
      shortHint: "保留统计分布特征（日期留年月、数字划区间、文字截断）；点「⚙ 参数」选择方式",
      paramHint: "日期只留年月/年份无需填参数值；数字按区间归类/四舍五入/文字截断可填写跨度或保留字数。",
      hasParams: true
    },
    {
      value: "regex_replace",
      label: "按格式局部替换（高级）",
      desc: "按自定义格式规则，只替换字段中符合条件的那一部分（如 EMP-123456 变为 EMP-****56）",
      shortHint: "按 Python 正则局部替换（分组用 \\\\1、\\\\2，勿用 $1）；必填「匹配格式」",
      paramHint: "使用 Python 正则语法，反向引用请用 \\\\1、\\\\2（勿用 $1）；如 (\\\\d{3})\\\\d{4}(\\\\d{4}) 替换为 \\\\1****\\\\2。",
      hasParams: true
    },
    {
      value: "inline_text",
      label: "长文本隐私清洗",
      desc: "保留正常业务文字，仅自动给其中夹带的手机号、身份证、银行卡、邮箱等打星号",
      shortHint: "仅清洗夹带的手机/身份证/银行卡/固话/邮箱/IP；姓名/公司/编码请换用星号或代号",
      paramHint: "",
      hasParams: false
    },
    {
      value: "obfuscate",
      label: "数据混淆（同长度同格式文本混淆）",
      desc: "保持原长度、标点与字符类型（数字换数字、字母换字母、汉字换汉字），每次随机打散关联",
      shortHint: "保持原长度、标点与字符类型（数字换数字、字母换字母、汉字换汉字），每次随机打散关联",
      paramHint: "默认全串按格式随机混淆；可设保留前/后几位（如保留后3位“-单体”），或切为同名同混淆。",
      hasParams: true
    },
    {
      value: "none",
      label: "不脱敏（原样保留）",
      desc: "该列不做任何修改，按原内容直接导出",
      shortHint: "原样保留导出，不做任何脱敏处理",
      paramHint: "",
      hasParams: false
    }
  ];
  const RULE_MAP = Object.fromEntries(RULES.map((r) => [r.value, r]));
  const RULE_LABELS_ZH = {
    mask_keep: "星号遮挡（保留首尾）",
    hash_sha256: "加密代号替换（同名同码）",
    redact: "整格替换为固定文字",
    generalize: "模糊化处理（留年月/划区间/截断）",
    regex_replace: "按格式局部替换（高级）",
    inline_text: "长文本隐私清洗",
    obfuscate: "数据混淆（同长度同格式）",
    none: "不脱敏（原样保留）"
  };
  const VALUE_KIND_MAP = {
    text: "文本",
    number: "数字",
    date: "日期",
    bool: "布尔",
    mixed: "混合",
    empty: "空列"
  };
  const SALT_MODE_MAP = {
    global: "全局统一口令",
    per_column: "按列独立口令",
    auto_generated: "系统自动生成临时口令",
    mixed: "全局+按列口令",
    none: "未启用加密口令"
  };

  const state = {
    currentStep: 1,
    sourceMode: "upload",
    fileId: null,
    uploadFilename: null,
    uploadSize: 0,
    localPath: "",
    inspectData: null,
    activeSheetIdx: 0,
    sheetConfigs: {}, // sheetName -> { colName -> { enabled, rule, sensitive_type, params } }
    sheetPreviews: {}, // sheetName -> { colName -> { samples, error } }
    previewTimers: {}, // sheetName -> timeoutId
    previewPendingCols: {}, // sheetName -> Set<colName>
    previewSeq: {}, // sheetName + "::" + colName -> number
    selectedCols: {}, // sheetName -> Set<colName>
    openParamCols: {}, // sheetName -> Set<colName>
    lastClickedIdx: null,
    lastJobId: null,
    isApplying: false
  };

  const $ = (id) => document.getElementById(id);

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function showStatus(elId, type, msg) {
    const el = $(elId);
    if (!el) return;
    el.className = "status-box show status-" + type;
    el.textContent = msg;
  }

  function clearStatus(elId) {
    const el = $(elId);
    if (!el) return;
    el.className = "status-box";
    el.textContent = "";
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  }

  function getBasename(pathStr) {
    const parts = String(pathStr || "").split(/[/\\\\]/);
    return parts[parts.length - 1] || pathStr || "";
  }

  function getCurrentSheet() {
    const sheets = state.inspectData?.sheets || [];
    return sheets[state.activeSheetIdx] || null;
  }

  function getSelectedSet(sheetName) {
    if (!sheetName) return new Set();
    if (!state.selectedCols[sheetName]) {
      state.selectedCols[sheetName] = new Set();
    }
    return state.selectedCols[sheetName];
  }

  function getOpenParamSet(sheetName) {
    if (!sheetName) return new Set();
    if (!state.openParamCols[sheetName]) {
      state.openParamCols[sheetName] = new Set();
    }
    return state.openParamCols[sheetName];
  }

  function updateSourceCapsule() {
    const cap = $("sourceCapsule");
    const shouldShow = state.currentStep > 1 && (Boolean(state.uploadFilename) || Boolean(state.localPath));
    if (!shouldShow) {
      cap.classList.add("hidden");
      return;
    }
    if (state.sourceMode === "upload" && state.uploadFilename) {
      $("capsuleFileName").textContent = state.uploadFilename;
      $("capsuleFileMeta").textContent = formatBytes(state.uploadSize || 0);
    } else {
      $("capsuleFileName").textContent = getBasename(state.localPath);
      $("capsuleFileMeta").textContent = "本机路径";
    }
    $("capsuleReuploadBtn").disabled = state.isApplying;
    cap.classList.remove("hidden");
  }

  function updateStepperUI() {
    const step = state.currentStep;
    for (let i = 1; i <= 4; i++) {
      const item = $("stepperStep" + i);
      const circle = $("stepCircle" + i);
      item.classList.remove("is-done", "is-active", "is-clickable");
      if (i < step) {
        item.classList.add("is-done");
        circle.textContent = "✓";
        if (!state.isApplying && (i === 1 || (i === 2 && state.inspectData))) {
          item.classList.add("is-clickable");
        }
      } else if (i === step) {
        item.classList.add("is-active");
        circle.textContent = String(i);
      } else {
        circle.textContent = String(i);
      }
      if (i < 4) {
        const line = $("stepLine" + i);
        line.classList.toggle("is-done", i < step);
      }
    }
  }

  function goToStep(stepNum) {
    state.currentStep = stepNum;
    $("step1Card").classList.toggle("hidden", stepNum !== 1);
    $("step2Card").classList.toggle("hidden", stepNum !== 2);
    $("step3Progress").classList.toggle("hidden", stepNum !== 3);
    $("step4Card").classList.toggle("hidden", stepNum !== 4);
    $("resumeStep2Btn").classList.toggle("hidden", !(stepNum === 1 && Boolean(state.inspectData)));
    updateSourceCapsule();
    updateStepperUI();
  }

  function resetStep3() {
    state.lastJobId = null;
    $("step3Progress").classList.add("hidden");
    $("step4Card").classList.add("hidden");
    $("resultStats").innerHTML = "";
    $("resultSheetsTbody").innerHTML = "";
    const notice = $("outputPathNotice");
    notice.textContent = "";
    notice.className = "status-box status-ok";
    if (state.currentStep >= 3) {
      goToStep(state.inspectData ? 2 : 1);
    } else {
      updateStepperUI();
    }
  }

  function clearPreviewState() {
    for (const key of Object.keys(state.previewTimers || {})) {
      clearTimeout(state.previewTimers[key]);
    }
    state.sheetPreviews = {};
    state.previewTimers = {};
    state.previewPendingCols = {};
    state.previewSeq = {};
  }

  function resetStep2() {
    clearPreviewState();
    state.inspectData = null;
    state.activeSheetIdx = 0;
    state.sheetConfigs = {};
    state.selectedCols = {};
    state.openParamCols = {};
    state.lastClickedIdx = null;
    $("step2Card").classList.add("hidden");
    $("fileMetaBar").innerHTML = "";
    $("sheetTabs").innerHTML = "";
    $("sheetTabs").classList.add("hidden");
    $("columnsTbody").innerHTML = "";
    $("resumeStep2Btn").classList.add("hidden");
    clearStatus("step2Status");
    updateBatchBar();
    updateWizardFooterStats();
  }

  function showUploadedCard(filename, size) {
    $("uploadedFileName").textContent = filename;
    $("uploadedFileSize").textContent = "(" + formatBytes(size) + ")";
    $("dropzoneEmpty").classList.add("hidden");
    $("uploadedFileCard").classList.remove("hidden");
    $("dropzone").classList.add("has-file");
  }

  function resetUploadUI() {
    state.fileId = null;
    state.uploadFilename = null;
    state.uploadSize = 0;
    $("fileInput").value = "";
    $("uploadedFileName").textContent = "";
    $("uploadedFileSize").textContent = "";
    $("uploadedFileCard").classList.add("hidden");
    $("dropzoneEmpty").classList.remove("hidden");
    $("dropzone").classList.remove("has-file");
    updateSourceCapsule();
  }

  function countEnabledMaskColumns() {
    let total = 0;
    for (const sName of Object.keys(state.sheetConfigs)) {
      const cols = state.sheetConfigs[sName] || {};
      for (const cName of Object.keys(cols)) {
        if (cols[cName] && cols[cName].rule !== "none") {
          total += 1;
        }
      }
    }
    return total;
  }

  function updateWizardFooterStats() {
    const enabledCount = countEnabledMaskColumns();
    $("enabledMaskCount").textContent = String(enabledCount);
    const sheet = getCurrentSheet();
    const selCount = sheet ? getSelectedSet(sheet.sheet_name).size : 0;
    $("footerSelectionHint").textContent = selCount > 0 ? ("（当前工作表已多选 " + selCount + " 列）") : "";
  }

  function updateAdvSummary() {
    const saltVal = $("globalSaltInput").value.trim();
    const wVal = $("workersInput").value.trim();
    const parts = [];
    if (saltVal) parts.push("已设口令");
    parts.push("线程 " + (wVal || "默认 8"));
    $("advSummaryTag").textContent = parts.join(" · ");
  }

  function initBatchRuleSelect() {
    const sel = $("batchRuleSelect");
    sel.innerHTML = "";
    for (const r of RULES) {
      const opt = document.createElement("option");
      opt.value = r.value;
      opt.textContent = r.label;
      opt.title = r.desc;
      sel.appendChild(opt);
    }
    sel.value = "mask_keep";
    sel.title = RULE_MAP[sel.value]?.desc || "";
    sel.addEventListener("change", () => {
      sel.title = RULE_MAP[sel.value]?.desc || "";
    });
  }
  initBatchRuleSelect();

  async function readFileBytes(file) {
    if (typeof file.arrayBuffer === "function") {
      return await file.arrayBuffer();
    }
    return await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error || new Error("读取文件失败"));
      reader.readAsArrayBuffer(file);
    });
  }

  async function apiJson(url, payload) {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Local-Token": TOKEN
      },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();
    if (!resp.ok || data.ok === false || data.status === "error") {
      throw new Error(data.error || ("请求失败: HTTP " + resp.status));
    }
    return data;
  }

  async function clearServerUpload(fileId) {
    if (!fileId) return;
    try {
      await apiJson("/api/upload/clear", { file_id: fileId });
    } catch (_err) {
      // Ignore cleanup errors so UI reset never blocks user re-upload
    }
  }

  // Stepper back navigation
  $("stepperStep1").addEventListener("click", () => {
    if (!state.isApplying && state.currentStep > 1) {
      goToStep(1);
    }
  });
  $("stepperStep2").addEventListener("click", () => {
    if (!state.isApplying && state.currentStep > 2 && state.inspectData) {
      goToStep(2);
    }
  });

  // Top Capsule Re-upload
  $("capsuleReuploadBtn").addEventListener("click", () => {
    if (state.isApplying) return;
    resetStep3();
    goToStep(1);
  });

  // Rule guide panel smooth toggle + click-to-copy regex examples
  let guideCloseTimer = null;
  function setRuleGuideOpen(open) {
    const panel = $("ruleGuidePanel");
    const btn = $("ruleGuideToggleBtn");
    if (!panel || !btn) return;
    if (guideCloseTimer) {
      clearTimeout(guideCloseTimer);
      guideCloseTimer = null;
    }
    btn.classList.toggle("is-open", open);
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    panel.setAttribute("aria-hidden", open ? "false" : "true");
    if (open) {
      panel.classList.remove("hidden");
      void panel.offsetWidth;
      panel.classList.add("is-open");
    } else {
      panel.classList.remove("is-open");
      guideCloseTimer = setTimeout(() => {
        if (!panel.classList.contains("is-open")) {
          panel.classList.add("hidden");
        }
        guideCloseTimer = null;
      }, 280);
    }
  }
  $("ruleGuideToggleBtn").addEventListener("click", () => {
    const isOpen = $("ruleGuidePanel").classList.contains("is-open");
    setRuleGuideOpen(!isOpen);
  });
  $("ruleGuidePanel").addEventListener("click", async (e) => {
    const codeEl = e.target.closest(".guide-copy-code");
    if (!codeEl) return;
    const text = codeEl.getAttribute("data-copy") || codeEl.textContent || "";
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      }
      codeEl.classList.add("is-copied");
      const orig = codeEl.textContent;
      codeEl.textContent = orig + " (已复制)";
      setTimeout(() => {
        codeEl.classList.remove("is-copied");
        codeEl.textContent = orig;
      }, 1100);
    } catch (_) {
      // Fallback: select text so user can Ctrl/Cmd+C manually
      const range = document.createRange();
      range.selectNodeContents(codeEl);
      const selection = window.getSelection();
      if (selection) {
        selection.removeAllRanges();
        selection.addRange(range);
      }
    }
  });

  // Advanced settings toggle
  $("advToggleBtn").addEventListener("click", () => {
    const panel = $("advSettingsPanel");
    const isHidden = panel.classList.toggle("hidden");
    const isOpen = !isHidden;
    $("advToggleBtn").classList.toggle("is-open", isOpen);
    $("advToggleBtn").setAttribute("aria-expanded", isOpen ? "true" : "false");
  });
  $("globalSaltInput").addEventListener("input", () => {
    updateAdvSummary();
    refreshHashPreviews(150);
  });
  $("workersInput").addEventListener("input", updateAdvSummary);

  // Source mode tabs
  $("tabUploadBtn").addEventListener("click", () => {
    state.sourceMode = "upload";
    $("tabUploadBtn").classList.add("active");
    $("tabPathBtn").classList.remove("active");
    $("panelUpload").classList.remove("hidden");
    $("panelPath").classList.add("hidden");
  });

  $("tabPathBtn").addEventListener("click", () => {
    state.sourceMode = "path";
    $("tabPathBtn").classList.add("active");
    $("tabUploadBtn").classList.remove("active");
    $("panelPath").classList.remove("hidden");
    $("panelUpload").classList.add("hidden");
  });

  $("localPathInput").addEventListener("input", () => {
    const val = $("localPathInput").value.trim();
    if (val !== state.localPath) {
      resetStep2();
      resetStep3();
    }
  });

  // Upload handlers
  const dropzone = $("dropzone");
  const fileInput = $("fileInput");

  dropzone.addEventListener("click", () => {
    if (!state.fileId) {
      fileInput.click();
    }
  });
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleUploadFile(e.dataTransfer.files[0]);
    }
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files.length > 0) {
      handleUploadFile(fileInput.files[0]);
    }
  });

  $("clearUploadBtn").addEventListener("click", async (e) => {
    e.stopPropagation();
    const prevFileId = state.fileId;
    resetUploadUI();
    resetStep2();
    resetStep3();
    clearStatus("step1Status");
    $("inspectMeta").textContent = "支持单表或多工作表全量扫描";
    await clearServerUpload(prevFileId);
  });

  async function handleUploadFile(file) {
    const prevFileId = state.fileId;
    clearStatus("step1Status");
    resetStep2();
    resetStep3();
    showStatus("step1Status", "info", "正在将文件读取并上传至本地会话目录...");
    try {
      const buf = await readFileBytes(file);
      const url = "/api/upload?filename=" + encodeURIComponent(file.name);
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-Local-Token": TOKEN
        },
        body: buf
      });
      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        throw new Error(data.error || "上传失败");
      }
      if (prevFileId && prevFileId !== data.file_id) {
        clearServerUpload(prevFileId);
      }
      state.fileId = data.file_id;
      state.uploadFilename = data.filename;
      state.uploadSize = data.size || 0;
      showUploadedCard(data.filename, data.size);
      showStatus("step1Status", "ok", "文件已就绪，请点击右下角“本地全量识别 →”。");
    } catch (err) {
      resetUploadUI();
      showStatus("step1Status", "err", err.message || "上传出错");
    }
  }

  $("resumeStep2Btn").addEventListener("click", () => {
    if (state.inspectData) {
      goToStep(2);
    }
  });

  // Inspect -> auto-advance to Step 2
  $("inspectBtn").addEventListener("click", async () => {
    clearStatus("step1Status");
    clearStatus("step2Status");
    resetStep3();
    const payload = {};
    if (state.sourceMode === "upload") {
      if (!state.fileId) {
        showStatus("step1Status", "err", "请先拖拽或选择一个 Excel / CSV 文件。");
        return;
      }
      payload.file_id = state.fileId;
    } else {
      const lp = $("localPathInput").value.trim();
      if (!lp) {
        showStatus("step1Status", "err", "请输入本机文件的完整路径。");
        return;
      }
      state.localPath = lp;
      payload.local_path = lp;
    }

    $("inspectBtn").disabled = true;
    showStatus("step1Status", "info", "正在执行本地全量流式扫描，请稍候...");
    try {
      const data = await apiJson("/api/inspect", payload);
      clearPreviewState();
      state.inspectData = data;
      state.activeSheetIdx = 0;
      state.selectedCols = {};
      state.openParamCols = {};
      state.lastClickedIdx = null;
      initSheetConfigs(data);
      renderInspectResult();
      clearStatus("step1Status");
      goToStep(2);
    } catch (err) {
      showStatus("step1Status", "err", err.message || "识别失败");
    } finally {
      $("inspectBtn").disabled = false;
    }
  });

  function initSheetConfigs(data) {
    state.sheetConfigs = {};
    for (const sheet of data.sheets || []) {
      const colsMap = {};
      for (const col of sheet.columns || []) {
        const defaultRule = col.is_sensitive ? (col.recommended_rule || "mask_keep") : "none";
        colsMap[col.col_name] = {
          enabled: defaultRule !== "none",
          rule: defaultRule,
          sensitive_type: col.sensitive_type || null,
          params: {}
        };
      }
      state.sheetConfigs[sheet.sheet_name] = colsMap;
    }
  }

  function renderInspectResult() {
    const data = state.inspectData;
    const sheets = data.sheets || [];
    const totalRows = sheets.reduce((acc, s) => acc + (s.data_rows || 0), 0);
    const totalSens = sheets.reduce(
      (acc, s) => acc + (s.columns || []).filter((c) => c.is_sensitive).length,
      0
    );

    $("fileMetaBar").innerHTML =
      "<span>格式: <strong>" + escapeHtml(data.format) + "</strong></span>" +
      "<span>引擎: <strong>" + escapeHtml(data.engine_used) + "</strong></span>" +
      "<span>工作表: <strong>" + sheets.length + "</strong></span>" +
      "<span>数据行: <strong>" + totalRows + "</strong></span>" +
      "<span>敏感列: <strong>" + totalSens + "</strong></span>" +
      "<span>耗时: <strong>" + data.elapsed_ms + " ms</strong></span>";

    const tabsEl = $("sheetTabs");
    tabsEl.innerHTML = "";
    if (sheets.length > 1) {
      tabsEl.classList.remove("hidden");
      sheets.forEach((s, idx) => {
        const sensCount = (s.columns || []).filter((c) => c.is_sensitive).length;
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "sheet-tab-btn" + (idx === state.activeSheetIdx ? " active" : "");
        btn.textContent = s.sheet_name + " (" + s.data_rows + "行 / " + sensCount + "敏感)";
        btn.addEventListener("click", () => {
          state.activeSheetIdx = idx;
          state.lastClickedIdx = null;
          renderInspectResult();
        });
        tabsEl.appendChild(btn);
      });
    } else {
      tabsEl.classList.add("hidden");
    }

    renderColumnsTable();
  }

  function updateBatchBar() {
    const sheet = getCurrentSheet();
    const cols = sheet ? (sheet.columns || []) : [];
    const selectedSet = sheet ? getSelectedSet(sheet.sheet_name) : new Set();
    const count = selectedSet.size;
    $("selectedCount").textContent = String(count);
    $("batchApplyBtn").disabled = count === 0;
    $("batchDisableBtn").disabled = count === 0;

    const allChk = $("selectAllChk");
    if (allChk) {
      if (cols.length === 0 || count === 0) {
        allChk.checked = false;
        allChk.indeterminate = false;
      } else if (count >= cols.length) {
        allChk.checked = true;
        allChk.indeterminate = false;
      } else {
        allChk.checked = false;
        allChk.indeterminate = true;
      }
    }
    updateWizardFooterStats();
  }

  function syncSelectionVisuals() {
    const sheet = getCurrentSheet();
    if (!sheet) {
      updateBatchBar();
      return;
    }
    const selectedSet = getSelectedSet(sheet.sheet_name);
    const rows = $("columnsTbody").querySelectorAll("tr[data-col-name]");
    rows.forEach((tr) => {
      const colName = tr.getAttribute("data-col-name");
      const isSelected = selectedSet.has(colName);
      tr.classList.toggle("row-selected", isSelected);
      const chk = tr.querySelector("input.row-select-chk");
      if (chk) chk.checked = isSelected;
    });
    updateBatchBar();
  }

  function getRowClassName(cfg, isSelected) {
    const classes = [];
    if (cfg.rule === "none") classes.push("row-disabled-rule");
    if (isSelected) classes.push("row-selected");
    return classes.join(" ");
  }

  function hasCustomParams(cfg) {
    if (!cfg || !cfg.params) return false;
    return Object.keys(cfg.params).length > 0;
  }

  function findPreviewCell(colName) {
    const cells = $("columnsTbody").querySelectorAll("td[data-preview-col]");
    for (const cell of cells) {
      if (cell.getAttribute("data-preview-col") === colName) {
        return cell;
      }
    }
    return null;
  }

  function renderPreviewCell(tdPrev, col, cfg, previewData) {
    if (!tdPrev) return;
    if (previewData && previewData.error) {
      const errText = String(previewData.error);
      tdPrev.innerHTML =
        "<div class='preview-stack'>" +
          "<span class='preview-pill preview-pill-error' title='" + escapeHtml(errText) + "'>⚠ " + escapeHtml(errText) + "</span>" +
        "</div>";
      return;
    }

    if (previewData && !previewData.error) {
      const samples = Array.isArray(previewData.samples) ? previewData.samples.slice(0, 3) : [];
      if (samples.length === 0) {
        tdPrev.innerHTML = "<span class='preview-pill preview-pill-muted'>[空列，无样本]</span>";
        return;
      }
      if (!cfg || cfg.rule === "none") {
        const pills = samples
          .map((p) => "<span class='preview-pill preview-pill-raw' title='" + escapeHtml(p) + "'>" + escapeHtml(p) + "</span>")
          .join("");
        tdPrev.innerHTML = "<div class='preview-stack'><span class='preview-origin-tag'>原样</span>" + pills + "</div>";
        return;
      }
      if (previewData.unchanged === true) {
        const pills = samples
          .map((p) => "<span class='preview-pill preview-pill-unchanged' title='" + escapeHtml(p) + "'>" + escapeHtml(p) + "</span>")
          .join("");
        tdPrev.innerHTML =
          "<div class='preview-unchanged-wrap'>" +
            "<div class='preview-unchanged-note'>⚠ 未命中规则（内容未变，可换用“星号遮挡”或“加密代号替换”）</div>" +
            "<div class='preview-stack'>" + pills + "</div>" +
          "</div>";
        return;
      }
      const pills = samples
        .map((p) => "<span class='preview-pill preview-pill-masked' title='" + escapeHtml(p) + "'>" + escapeHtml(p) + "</span>")
        .join("");
      tdPrev.innerHTML = "<div class='preview-stack'>" + pills + "</div>";
      return;
    }

    if (col && col.non_null_count === 0) {
      tdPrev.innerHTML = "<span class='preview-pill preview-pill-muted'>[空列，无样本]</span>";
      return;
    }
    if (cfg && cfg.rule !== "none" && col && col.is_sensitive && Array.isArray(col.masked_previews) && col.masked_previews.length > 0 && !hasCustomParams(cfg)) {
      const pills = col.masked_previews
        .slice(0, 3)
        .map((p) => "<span class='preview-pill preview-pill-masked' title='" + escapeHtml(p) + "'>" + escapeHtml(p) + "</span>")
        .join("");
      tdPrev.innerHTML = "<div class='preview-stack'>" + pills + "</div>";
      return;
    }
    tdPrev.innerHTML = "<span class='preview-pill preview-pill-muted'>预览计算中…</span>";
  }

  async function fetchSheetPreviews(sheetName, colNames) {
    if (!state.inspectData || !sheetName || !Array.isArray(colNames) || colNames.length === 0) {
      return;
    }
    const sheetCfg = state.sheetConfigs[sheetName] || {};
    const columnsPayload = {};
    for (const cName of colNames) {
      const cfg = sheetCfg[cName];
      if (!cfg) continue;
      columnsPayload[cName] = {
        rule: cfg.rule || "none",
        sensitive_type: cfg.sensitive_type || null,
        params: Object.assign({}, cfg.params || {})
      };
    }
    const reqColNames = Object.keys(columnsPayload);
    if (reqColNames.length === 0) return;

    const payload = {
      sheet_name: sheetName,
      global_salt: $("globalSaltInput").value.trim(),
      columns: columnsPayload
    };
    if (state.sourceMode === "upload") {
      if (!state.fileId) return;
      payload.file_id = state.fileId;
    } else {
      if (!state.localPath) return;
      payload.local_path = state.localPath;
    }

    const reqSeqMap = {};
    for (const cName of reqColNames) {
      const seqKey = sheetName + "::" + cName;
      state.previewSeq[seqKey] = (state.previewSeq[seqKey] || 0) + 1;
      reqSeqMap[cName] = state.previewSeq[seqKey];
    }

    try {
      const res = await apiJson("/api/preview", payload);
      if (!state.inspectData) return;
      if (!state.sheetPreviews[sheetName]) {
        state.sheetPreviews[sheetName] = {};
      }
      const curSheet = getCurrentSheet();
      const targetSheetObj = (state.inspectData.sheets || []).find((s) => s.sheet_name === sheetName);
      const colMetaMap = {};
      for (const c of (targetSheetObj?.columns || [])) {
        colMetaMap[c.col_name] = c;
      }
      const latestCfg = state.sheetConfigs[sheetName] || {};
      const resPreviews = res.previews || {};

      for (const cName of Object.keys(resPreviews)) {
        const seqKey = sheetName + "::" + cName;
        if (state.previewSeq[seqKey] !== reqSeqMap[cName]) {
          continue;
        }
        const prevData = resPreviews[cName];
        state.sheetPreviews[sheetName][cName] = prevData;
        if (curSheet && curSheet.sheet_name === sheetName) {
          const tdPrev = findPreviewCell(cName);
          if (tdPrev) {
            renderPreviewCell(tdPrev, colMetaMap[cName] || { col_name: cName }, latestCfg[cName], prevData);
          }
        }
      }
    } catch (err) {
      if (!state.inspectData) return;
      const curSheet = getCurrentSheet();
      if (!curSheet || curSheet.sheet_name !== sheetName) return;
      const errMsg = err?.message || "预览失败";
      for (const cName of reqColNames) {
        const seqKey = sheetName + "::" + cName;
        if (state.previewSeq[seqKey] !== reqSeqMap[cName]) {
          continue;
        }
        const tdPrev = findPreviewCell(cName);
        if (tdPrev) {
          renderPreviewCell(tdPrev, { col_name: cName }, (state.sheetConfigs[sheetName] || {})[cName], {
            samples: [],
            error: errMsg
          });
        }
      }
    }
  }

  function schedulePreview(sheetName, colNames, delayMs) {
    if (!sheetName || !Array.isArray(colNames) || colNames.length === 0) return;
    if (!state.previewPendingCols[sheetName]) {
      state.previewPendingCols[sheetName] = new Set();
    }
    for (const cName of colNames) {
      state.previewPendingCols[sheetName].add(cName);
    }
    if (state.previewTimers[sheetName]) {
      clearTimeout(state.previewTimers[sheetName]);
      delete state.previewTimers[sheetName];
    }
    const flush = () => {
      delete state.previewTimers[sheetName];
      const pending = Array.from(state.previewPendingCols[sheetName] || []);
      if (state.previewPendingCols[sheetName]) {
        state.previewPendingCols[sheetName].clear();
      }
      if (pending.length > 0) {
        fetchSheetPreviews(sheetName, pending);
      }
    };
    const wait = typeof delayMs === "number" ? delayMs : 150;
    if (wait <= 0) {
      flush();
    } else {
      state.previewTimers[sheetName] = setTimeout(flush, wait);
    }
  }

  function refreshHashPreviews(delayMs) {
    const sheet = getCurrentSheet();
    if (!sheet) return;
    const sheetCfg = state.sheetConfigs[sheet.sheet_name] || {};
    const hashCols = (sheet.columns || [])
      .map((c) => c.col_name)
      .filter((cName) => {
        const c = sheetCfg[cName];
        return c && (c.rule === "hash_sha256" || (c.rule === "obfuscate" && c.params?.mode === "consistent"));
      });
    if (hashCols.length > 0) {
      schedulePreview(sheet.sheet_name, hashCols, delayMs);
    }
  }

  function renderColumnsTable() {
    const tbody = $("columnsTbody");
    tbody.innerHTML = "";
    const sheet = getCurrentSheet();
    if (!sheet) {
      updateBatchBar();
      return;
    }
    const sheetCfg = state.sheetConfigs[sheet.sheet_name] || {};
    const sheetPrev = state.sheetPreviews[sheet.sheet_name] || {};
    const selectedSet = getSelectedSet(sheet.sheet_name);
    const openParamSet = getOpenParamSet(sheet.sheet_name);
    const cols = sheet.columns || [];

    cols.forEach((col, idx) => {
      const cfg = sheetCfg[col.col_name];
      cfg.enabled = cfg.rule !== "none";
      const isSelected = selectedSet.has(col.col_name);
      const tr = document.createElement("tr");
      tr.setAttribute("data-col-name", col.col_name);
      tr.className = getRowClassName(cfg, isSelected);

      // 1. Checkbox
      const tdChk = document.createElement("td");
      tdChk.style.textAlign = "center";
      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.className = "row-select-chk";
      chk.checked = isSelected;
      chk.title = "点击选择此列（按住 Shift 键可范围连选）";
      chk.addEventListener("click", (e) => {
        const targetChecked = chk.checked;
        if (e.shiftKey && state.lastClickedIdx !== null && state.lastClickedIdx >= 0 && state.lastClickedIdx < cols.length) {
          const start = Math.min(state.lastClickedIdx, idx);
          const end = Math.max(state.lastClickedIdx, idx);
          for (let i = start; i <= end; i++) {
            const cName = cols[i].col_name;
            if (targetChecked) selectedSet.add(cName);
            else selectedSet.delete(cName);
          }
        } else {
          if (targetChecked) selectedSet.add(col.col_name);
          else selectedSet.delete(col.col_name);
        }
        state.lastClickedIdx = idx;
        syncSelectionVisuals();
      });
      tdChk.appendChild(chk);
      tr.appendChild(tdChk);

      // 2. Source Field (Name + Kind Badge + Sensitivity / Inline Risk)
      const tdSource = document.createElement("td");
      tdSource.className = "col-source-cell";
      let kindLabel = VALUE_KIND_MAP[col.value_kind] || col.value_kind || "未知";
      if (col.value_kind === "text" && (col.max_len || 0) >= 35) {
        kindLabel = "长文本";
      }
      const confPct = ((col.confidence || 0) * 100).toFixed(0) + "%";
      const hitPct = ((col.hit_rate || 0) * 100).toFixed(1) + "%";
      const detailTitle = "非空 " + col.non_null_count + " 行 · 长度 " + col.min_len + "~" + col.max_len + " · 匹配率 " + hitPct + " (" + (col.hits || 0) + ")";

      let riskBadgeHtml = "";
      if (col.is_sensitive) {
        riskBadgeHtml = "<span class='tag tag-sens' title='" + escapeHtml(detailTitle) + "'>" +
          escapeHtml(col.sensitive_label || "敏感信息") + " · " + confPct + "</span>";
      } else if (col.inline_hint) {
        riskBadgeHtml = "<span class='tag tag-inline' title='" + escapeHtml(detailTitle) + "'>偶发内嵌敏感</span>";
      }

      tdSource.innerHTML =
        "<div class='source-main'>" +
          "<span class='col-name-text' title='" + escapeHtml(detailTitle) + "'>" + escapeHtml(col.col_name) + "</span>" +
          "<span class='kind-badge' title='" + escapeHtml(detailTitle) + "'>" + escapeHtml(kindLabel) + "</span>" +
          riskBadgeHtml +
        "</div>" +
        "<div class='source-sub'>" +
          "<span>非空 " + col.non_null_count + "</span>" +
          "<span>·</span>" +
          "<span>长度 " + col.min_len + "~" + col.max_len + "</span>" +
          (col.is_sensitive ? ("<span>·</span><span>匹配 " + hitPct + "</span>") : "") +
        "</div>";
      tr.appendChild(tdSource);

      // 3. Arrow
      const tdArrow = document.createElement("td");
      tdArrow.className = "arrow-cell";
      tdArrow.textContent = "→";
      tr.appendChild(tdArrow);

      // 4. Rule selector + lightweight parameter toggle & collapsible drawer
      const tdRule = document.createElement("td");
      tdRule.className = "rule-cell";

      const controlRow = document.createElement("div");
      controlRow.className = "rule-control-row";

      const sel = document.createElement("select");
      sel.className = "rule-select" + (cfg.rule === "none" ? " is-none" : "");
      for (const r of RULES) {
        const opt = document.createElement("option");
        opt.value = r.value;
        opt.textContent = r.label;
        opt.title = r.desc;
        if (cfg.rule === r.value) opt.selected = true;
        sel.appendChild(opt);
      }
      sel.title = RULE_MAP[cfg.rule]?.desc || "";

      const paramBtn = document.createElement("button");
      paramBtn.type = "button";
      paramBtn.className = "btn-param-toggle";
      paramBtn.textContent = "⚙ 参数";

      const inlineHint = document.createElement("div");
      inlineHint.className = "rule-inline-hint";

      const drawer = document.createElement("div");
      drawer.className = "inline-params-drawer";

      // 5. Preview cell
      const tdPrev = document.createElement("td");
      tdPrev.className = "preview-cell";
      tdPrev.setAttribute("data-preview-col", col.col_name);
      renderPreviewCell(tdPrev, col, cfg, sheetPrev[col.col_name] || null);

      const syncRuleWidgets = () => {
        const ruleMeta = RULE_MAP[cfg.rule] || {};
        const supportsParams = Boolean(ruleMeta.hasParams);
        sel.className = "rule-select" + (cfg.rule === "none" ? " is-none" : "");
        sel.title = ruleMeta.desc || "";
        inlineHint.textContent = ruleMeta.shortHint || ruleMeta.desc || "";

        if (!supportsParams) {
          openParamSet.delete(col.col_name);
          paramBtn.classList.add("hidden");
          drawer.classList.add("hidden");
          drawer.innerHTML = "";
        } else {
          paramBtn.classList.remove("hidden");
          const isOpen = openParamSet.has(col.col_name);
          const custom = hasCustomParams(cfg);
          paramBtn.classList.toggle("is-open", isOpen);
          paramBtn.classList.toggle("has-custom", custom);
          paramBtn.textContent = custom ? "⚙ 参数 •" : "⚙ 参数";
          drawer.classList.toggle("hidden", !isOpen);
          if (isOpen) {
            drawer.innerHTML = "";
            drawer.appendChild(buildParamsEditor(cfg, () => {
              const nowCustom = hasCustomParams(cfg);
              paramBtn.classList.toggle("has-custom", nowCustom);
              paramBtn.textContent = nowCustom ? "⚙ 参数 •" : "⚙ 参数";
              schedulePreview(sheet.sheet_name, [col.col_name], 150);
            }));
          }
        }
      };

      tr._syncRuleFromConfig = () => {
        sel.value = cfg.rule;
        tr.className = getRowClassName(cfg, selectedSet.has(col.col_name));
        syncRuleWidgets();
        renderPreviewCell(tdPrev, col, cfg, null);
      };

      paramBtn.addEventListener("click", () => {
        if (openParamSet.has(col.col_name)) {
          openParamSet.delete(col.col_name);
        } else {
          openParamSet.add(col.col_name);
        }
        syncRuleWidgets();
      });

      sel.addEventListener("change", () => {
        cfg.rule = sel.value;
        cfg.enabled = sel.value !== "none";
        cfg.params = {};
        if (cfg.rule === "regex_replace") {
          openParamSet.add(col.col_name);
        } else {
          openParamSet.delete(col.col_name);
        }
        tr.className = getRowClassName(cfg, selectedSet.has(col.col_name));
        syncRuleWidgets();
        renderPreviewCell(tdPrev, col, cfg, null);
        updateWizardFooterStats();
        schedulePreview(sheet.sheet_name, [col.col_name], 0);
      });

      syncRuleWidgets();
      controlRow.appendChild(sel);
      controlRow.appendChild(paramBtn);
      tdRule.appendChild(controlRow);
      tdRule.appendChild(inlineHint);
      tdRule.appendChild(drawer);
      tr.appendChild(tdRule);

      tr.appendChild(tdPrev);
      tbody.appendChild(tr);
    });

    updateBatchBar();
    if (cols.length > 0) {
      schedulePreview(sheet.sheet_name, cols.map((c) => c.col_name), 0);
    }
  }

  function buildParamsEditor(cfg, onChangeCb) {
    const wrap = document.createElement("div");
    const box = document.createElement("div");
    box.className = "param-box";
    wrap.appendChild(box);
    const paramHintText = RULE_MAP[cfg.rule]?.paramHint || "";
    if (paramHintText) {
      const hintEl = document.createElement("div");
      hintEl.className = "param-hint";
      hintEl.textContent = paramHintText;
      wrap.appendChild(hintEl);
    }
    const notify = () => {
      if (typeof onChangeCb === "function") onChangeCb();
    };

    if (cfg.rule === "mask_keep") {
      const f1 = document.createElement("label");
      f1.className = "param-field";
      f1.innerHTML = "<span>保留前几位</span>";
      const head = document.createElement("input");
      head.type = "number";
      head.min = "0";
      head.className = "param-mini";
      head.placeholder = "自动";
      if (cfg.params.keep_head !== undefined) head.value = cfg.params.keep_head;
      head.addEventListener("input", () => {
        if (head.value === "") delete cfg.params.keep_head;
        else cfg.params.keep_head = parseInt(head.value, 10);
        notify();
      });
      f1.appendChild(head);

      const f2 = document.createElement("label");
      f2.className = "param-field";
      f2.innerHTML = "<span>保留后几位</span>";
      const tail = document.createElement("input");
      tail.type = "number";
      tail.min = "0";
      tail.className = "param-mini";
      tail.placeholder = "自动";
      if (cfg.params.keep_tail !== undefined) tail.value = cfg.params.keep_tail;
      tail.addEventListener("input", () => {
        if (tail.value === "") delete cfg.params.keep_tail;
        else cfg.params.keep_tail = parseInt(tail.value, 10);
        notify();
      });
      f2.appendChild(tail);

      const f3 = document.createElement("label");
      f3.className = "param-field";
      f3.innerHTML = "<span>遮挡符号</span>";
      const mchar = document.createElement("input");
      mchar.type = "text";
      mchar.maxLength = 3;
      mchar.className = "param-mini";
      mchar.placeholder = "默认 *";
      if (cfg.params.mask_char !== undefined) mchar.value = cfg.params.mask_char;
      mchar.addEventListener("input", () => {
        if (mchar.value === "") delete cfg.params.mask_char;
        else cfg.params.mask_char = mchar.value;
        notify();
      });
      f3.appendChild(mchar);

      box.appendChild(f1);
      box.appendChild(f2);
      box.appendChild(f3);
      return wrap;
    }

    if (cfg.rule === "hash_sha256") {
      const f1 = document.createElement("label");
      f1.className = "param-field";
      f1.innerHTML = "<span>列独立口令（可空走全局）</span>";
      const saltIn = document.createElement("input");
      saltIn.type = "text";
      saltIn.className = "param-med";
      saltIn.placeholder = "留空则用全局/临时口令";
      if (cfg.params.salt !== undefined) saltIn.value = cfg.params.salt;
      saltIn.addEventListener("input", () => {
        if (saltIn.value === "") delete cfg.params.salt;
        else cfg.params.salt = saltIn.value;
        notify();
      });
      f1.appendChild(saltIn);

      const f2 = document.createElement("label");
      f2.className = "param-field";
      f2.innerHTML = "<span>代号长度</span>";
      const lenIn = document.createElement("input");
      lenIn.type = "number";
      lenIn.min = "4";
      lenIn.max = "64";
      lenIn.className = "param-mini";
      lenIn.placeholder = "默认 16";
      if (cfg.params.length !== undefined) lenIn.value = cfg.params.length;
      lenIn.addEventListener("input", () => {
        if (lenIn.value === "") delete cfg.params.length;
        else cfg.params.length = parseInt(lenIn.value, 10);
        notify();
      });
      f2.appendChild(lenIn);

      const f3 = document.createElement("label");
      f3.className = "param-field";
      f3.innerHTML = "<span>代号前缀</span>";
      const prefIn = document.createElement("input");
      prefIn.type = "text";
      prefIn.className = "param-mini";
      prefIn.placeholder = "如 H_";
      if (cfg.params.prefix !== undefined) prefIn.value = cfg.params.prefix;
      prefIn.addEventListener("input", () => {
        if (prefIn.value === "") delete cfg.params.prefix;
        else cfg.params.prefix = prefIn.value;
        notify();
      });
      f3.appendChild(prefIn);

      box.appendChild(f1);
      box.appendChild(f2);
      box.appendChild(f3);
      return wrap;
    }

    if (cfg.rule === "redact") {
      const f1 = document.createElement("label");
      f1.className = "param-field";
      f1.innerHTML = "<span>替换文本</span>";
      const repIn = document.createElement("input");
      repIn.type = "text";
      repIn.className = "param-med";
      repIn.placeholder = "默认 [已脱敏]";
      if (cfg.params.replacement !== undefined) repIn.value = cfg.params.replacement;
      repIn.addEventListener("input", () => {
        if (repIn.value === "") delete cfg.params.replacement;
        else cfg.params.replacement = repIn.value;
        notify();
      });
      f1.appendChild(repIn);
      box.appendChild(f1);
      return wrap;
    }

    if (cfg.rule === "generalize") {
      const f1 = document.createElement("label");
      f1.className = "param-field";
      f1.innerHTML = "<span>模糊方式</span>";
      const modeSel = document.createElement("select");
      modeSel.className = "param-med";
      const modes = [
        ["auto", "自动判断"],
        ["date_ym", "日期只留年月"],
        ["date_year", "日期只留年份"],
        ["number_bucket", "数字按区间归类"],
        ["number_round", "数字四舍五入取整"],
        ["truncate", "文字只留前几字"]
      ];
      for (const [mv, ml] of modes) {
        const o = document.createElement("option");
        o.value = mv;
        o.textContent = ml;
        if ((cfg.params.mode || "auto") === mv) o.selected = true;
        modeSel.appendChild(o);
      }
      f1.appendChild(modeSel);

      const f2 = document.createElement("label");
      f2.className = "param-field";
      const valLabel = document.createElement("span");
      valLabel.textContent = "参数值";
      const valIn = document.createElement("input");
      valIn.type = "number";
      valIn.className = "param-mini";
      const syncGenPlaceholder = () => {
        const m = cfg.params.mode || "auto";
        if (m === "number_bucket") {
          valIn.disabled = false;
          valLabel.textContent = "区间跨度";
          valIn.placeholder = "如 1000";
        } else if (m === "number_round") {
          valIn.disabled = false;
          valLabel.textContent = "小数位数";
          valIn.placeholder = "如 0 / -2";
        } else if (m === "truncate") {
          valIn.disabled = false;
          valLabel.textContent = "保留字数";
          valIn.placeholder = "如 4";
        } else {
          valIn.disabled = true;
          valLabel.textContent = "参数值";
          valIn.placeholder = "无需填写";
        }
      };
      syncGenPlaceholder();
      if (cfg.params.bucket !== undefined) valIn.value = cfg.params.bucket;
      else if (cfg.params.precision !== undefined) valIn.value = cfg.params.precision;
      else if (cfg.params.max_len !== undefined) valIn.value = cfg.params.max_len;

      modeSel.addEventListener("change", () => {
        cfg.params = { mode: modeSel.value };
        valIn.value = "";
        syncGenPlaceholder();
        notify();
      });
      valIn.addEventListener("input", () => {
        const m = cfg.params.mode || "auto";
        delete cfg.params.bucket;
        delete cfg.params.precision;
        delete cfg.params.max_len;
        if (valIn.value !== "") {
          const num = Number(valIn.value);
          if (m === "number_bucket") cfg.params.bucket = num;
          else if (m === "number_round") cfg.params.precision = parseInt(valIn.value, 10);
          else if (m === "truncate") cfg.params.max_len = parseInt(valIn.value, 10);
        }
        notify();
      });

      f2.appendChild(valLabel);
      f2.appendChild(valIn);
      box.appendChild(f1);
      box.appendChild(f2);
      return wrap;
    }

    if (cfg.rule === "regex_replace") {
      const f1 = document.createElement("label");
      f1.className = "param-field";
      f1.innerHTML = "<span>匹配格式（正则必填）</span>";
      const patIn = document.createElement("input");
      patIn.type = "text";
      patIn.className = "param-med mono";
      patIn.placeholder = "如 \\\\d{4}(?=\\\\d{2}$)";
      if (cfg.params.pattern !== undefined) patIn.value = cfg.params.pattern;
      patIn.addEventListener("input", () => {
        if (patIn.value === "") delete cfg.params.pattern;
        else cfg.params.pattern = patIn.value;
        notify();
      });
      f1.appendChild(patIn);

      const f2 = document.createElement("label");
      f2.className = "param-field";
      f2.innerHTML = "<span>替换为</span>";
      const repIn = document.createElement("input");
      repIn.type = "text";
      repIn.className = "param-mini mono";
      repIn.placeholder = "默认 ***";
      if (cfg.params.repl !== undefined) repIn.value = cfg.params.repl;
      repIn.addEventListener("input", () => {
        if (repIn.value === "") delete cfg.params.repl;
        else cfg.params.repl = repIn.value;
        notify();
      });
      f2.appendChild(repIn);

      box.appendChild(f1);
      box.appendChild(f2);
      return wrap;
    }

    if (cfg.rule === "obfuscate") {
      const f1 = document.createElement("label");
      f1.className = "param-field";
      f1.innerHTML = "<span>保留前几位 (默认0)</span>";
      const head = document.createElement("input");
      head.type = "number";
      head.min = "0";
      head.className = "param-mini";
      head.placeholder = "0";
      if (cfg.params.keep_head !== undefined) head.value = cfg.params.keep_head;
      head.addEventListener("input", () => {
        if (head.value === "") delete cfg.params.keep_head;
        else {
          const parsed = parseInt(head.value, 10);
          if (Number.isNaN(parsed) || parsed < 0) delete cfg.params.keep_head;
          else cfg.params.keep_head = parsed;
        }
        notify();
      });
      f1.appendChild(head);

      const f2 = document.createElement("label");
      f2.className = "param-field";
      f2.innerHTML = "<span>保留后几位 (默认0)</span>";
      const tail = document.createElement("input");
      tail.type = "number";
      tail.min = "0";
      tail.className = "param-mini";
      tail.placeholder = "0";
      if (cfg.params.keep_tail !== undefined) tail.value = cfg.params.keep_tail;
      tail.addEventListener("input", () => {
        if (tail.value === "") delete cfg.params.keep_tail;
        else {
          const parsed = parseInt(tail.value, 10);
          if (Number.isNaN(parsed) || parsed < 0) delete cfg.params.keep_tail;
          else cfg.params.keep_tail = parsed;
        }
        notify();
      });
      f2.appendChild(tail);

      const f3 = document.createElement("label");
      f3.className = "param-field";
      f3.innerHTML = "<span>混淆模式</span>";
      const modeSel = document.createElement("select");
      modeSel.className = "param-wide";
      const modes = [
        ["random", "每次随机混淆（默认，打散关联）"],
        ["consistent", "同名同混淆（按口令保持关联）"]
      ];
      for (const [mv, ml] of modes) {
        const o = document.createElement("option");
        o.value = mv;
        o.textContent = ml;
        if ((cfg.params.mode || "random") === mv) o.selected = true;
        modeSel.appendChild(o);
      }
      modeSel.addEventListener("change", () => {
        if (modeSel.value === "random") delete cfg.params.mode;
        else cfg.params.mode = modeSel.value;
        notify();
      });
      f3.appendChild(modeSel);

      box.appendChild(f1);
      box.appendChild(f2);
      box.appendChild(f3);
      return wrap;
    }

    return wrap;
  }

  // Multi-select quick actions (affect selection only, preserve column rules)
  function updateSelectionByMode(mode) {
    const sheet = getCurrentSheet();
    if (!sheet) return;
    const selectedSet = getSelectedSet(sheet.sheet_name);
    const cols = sheet.columns || [];
    if (mode === "all") {
      for (const col of cols) selectedSet.add(col.col_name);
    } else if (mode === "none") {
      selectedSet.clear();
    } else if (mode === "sensitive") {
      selectedSet.clear();
      for (const col of cols) {
        if (col.is_sensitive) selectedSet.add(col.col_name);
      }
    } else if (mode === "inline") {
      selectedSet.clear();
      for (const col of cols) {
        if (col.is_sensitive || col.inline_hint) selectedSet.add(col.col_name);
      }
    } else if (mode === "invert") {
      for (const col of cols) {
        if (selectedSet.has(col.col_name)) selectedSet.delete(col.col_name);
        else selectedSet.add(col.col_name);
      }
    }
    state.lastClickedIdx = null;
    syncSelectionVisuals();
  }

  $("selectAllChk").addEventListener("change", () => {
    updateSelectionByMode($("selectAllChk").checked ? "all" : "none");
  });
  $("selectAllBtn").addEventListener("click", () => updateSelectionByMode("all"));
  $("selectSensitiveBtn").addEventListener("click", () => updateSelectionByMode("sensitive"));
  $("selectInlineBtn").addEventListener("click", () => updateSelectionByMode("inline"));
  $("invertSelectBtn").addEventListener("click", () => updateSelectionByMode("invert"));
  $("unselectAllBtn").addEventListener("click", () => updateSelectionByMode("none"));

  // Batch rule application
  function applyBatchRule(ruleValue) {
    const sheet = getCurrentSheet();
    if (!sheet) return;
    const selectedSet = getSelectedSet(sheet.sheet_name);
    if (selectedSet.size === 0) return;

    const sheetCfg = state.sheetConfigs[sheet.sheet_name] || {};
    const openParamSet = getOpenParamSet(sheet.sheet_name);
    const updatedCols = [];
    for (const colName of selectedSet) {
      const cfg = sheetCfg[colName];
      if (!cfg) continue;
      cfg.rule = ruleValue;
      cfg.enabled = ruleValue !== "none";
      cfg.params = {};
      if (ruleValue === "regex_replace") {
        openParamSet.add(colName);
      } else {
        openParamSet.delete(colName);
      }
      updatedCols.push(colName);
    }
    const updatedSet = new Set(updatedCols);
    const rows = $("columnsTbody").querySelectorAll("tr[data-col-name]");
    rows.forEach((tr) => {
      const colName = tr.getAttribute("data-col-name");
      if (updatedSet.has(colName) && typeof tr._syncRuleFromConfig === "function") {
        tr._syncRuleFromConfig();
      }
    });
    updateWizardFooterStats();
    schedulePreview(sheet.sheet_name, updatedCols, 0);
    const ruleLabel = RULE_MAP[ruleValue]?.label || ruleValue;
    showStatus("step2Status", "info", "已将所选 " + updatedCols.length + " 列的脱敏规则批量设为：「" + ruleLabel + "」，未选列保持不变。");
  }

  $("batchApplyBtn").addEventListener("click", () => {
    applyBatchRule($("batchRuleSelect").value);
  });
  $("batchDisableBtn").addEventListener("click", () => {
    applyBatchRule("none");
  });

  $("genSaltBtn").addEventListener("click", () => {
    const arr = new Uint8Array(16);
    window.crypto.getRandomValues(arr);
    $("globalSaltInput").value = Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
    updateAdvSummary();
    refreshHashPreviews(0);
  });

  $("backToStep1Btn").addEventListener("click", () => {
    if (!state.isApplying) {
      goToStep(1);
    }
  });

  // Apply masking -> Step 3 (progress) -> Step 4 (result)
  $("applyBtn").addEventListener("click", async () => {
    clearStatus("step2Status");
    if (!state.inspectData || state.isApplying) return;

    const sheets = state.inspectData.sheets || [];
    const config = {
      global_salt: $("globalSaltInput").value.trim(),
      allow_unsalted: false,
      columns: {},
      sheets: {}
    };

    for (let sIdx = 0; sIdx < sheets.length; sIdx++) {
      const sheet = sheets[sIdx];
      const sCfg = state.sheetConfigs[sheet.sheet_name] || {};
      const outCols = {};
      for (const col of sheet.columns || []) {
        const c = sCfg[col.col_name];
        if (!c || !c.enabled || c.rule === "none") {
          outCols[col.col_name] = { rule: "none" };
          continue;
        }
        if (c.rule === "regex_replace" && !c.params.pattern) {
          state.activeSheetIdx = sIdx;
          getOpenParamSet(sheet.sheet_name).add(col.col_name);
          renderInspectResult();
          showStatus("step2Status", "err", "工作表 [" + sheet.sheet_name + "] 列 [" + col.col_name + "] 使用「按格式局部替换（高级）」时必须填写匹配格式。");
          return;
        }
        const entry = {
          rule: c.rule,
          params: Object.assign({}, c.params)
        };
        if (c.sensitive_type) entry.sensitive_type = c.sensitive_type;
        outCols[col.col_name] = entry;
      }
      config.sheets[sheet.sheet_name] = { columns: outCols };
    }

    const payload = { config: config };
    if (state.sourceMode === "upload") {
      payload.file_id = state.fileId;
    } else {
      payload.local_path = state.localPath;
    }
    const wVal = $("workersInput").value.trim();
    if (wVal !== "") {
      payload.workers = parseInt(wVal, 10);
    }

    const totalRows = sheets.reduce((acc, s) => acc + (s.data_rows || 0), 0);
    const enabledCount = countEnabledMaskColumns();
    $("progressMetaPills").innerHTML =
      "<span class='trust-item'>处理行数：" + totalRows + " 行</span>" +
      "<span class='trust-item'>脱敏字段：" + enabledCount + " 列</span>" +
      "<span class='trust-item'>并发线程：" + escapeHtml(wVal || "默认 8") + "</span>";

    state.isApplying = true;
    $("applyBtn").disabled = true;
    goToStep(3);

    try {
      const res = await apiJson("/api/apply", payload);
      state.lastJobId = res.job_id;
      state.isApplying = false;
      renderApplyResult(res);
      goToStep(4);
    } catch (err) {
      state.isApplying = false;
      goToStep(2);
      showStatus("step2Status", "err", err.message || "脱敏执行失败");
    } finally {
      state.isApplying = false;
      $("applyBtn").disabled = false;
      updateSourceCapsule();
      updateStepperUI();
    }
  });

  function renderApplyResult(res) {
    const saltModeLabel = SALT_MODE_MAP[res.salt_mode] || res.salt_mode || "已启用";
    const saltDesc = res.used_salt ? ("已启用（" + saltModeLabel + "）") : "未启用";
    $("resultStats").innerHTML =
      "<div class='stat-item'><div class='k'>处理总行数</div><div class='v'>" + res.total_rows_processed + "</div></div>" +
      "<div class='stat-item'><div class='k'>脱敏单元格数</div><div class='v'>" + res.total_cells_masked + "</div></div>" +
      "<div class='stat-item'><div class='k'>耗时</div><div class='v'>" + res.elapsed_ms + " ms</div></div>" +
      "<div class='stat-item'><div class='k'>吞吐速率</div><div class='v'>" + res.rows_per_sec + " 行/秒</div></div>" +
      "<div class='stat-item'><div class='k'>读写引擎</div><div class='v' style='font-size:14px;'>" + escapeHtml(res.read_engine + " → " + res.write_engine) + "</div></div>" +
      "<div class='stat-item'><div class='k'>加密口令状态</div><div class='v' style='font-size:14px;'>" + escapeHtml(saltDesc) + "</div></div>";

    const notice = $("outputPathNotice");
    notice.className = "status-box status-ok show";
    if (res.output_path) {
      notice.textContent = "本地输出文件路径：" + res.output_path + "（未覆盖原文件，可直接本地打开或点击右下角按钮下载）";
    } else {
      notice.textContent = "脱敏文件已在本地会话目录生成，请点击右下角“下载脱敏文件”按钮保存到本地。";
    }

    const tbody = $("resultSheetsTbody");
    tbody.innerHTML = "";
    for (const s of res.sheets || []) {
      const tr = document.createElement("tr");
      const colsDesc = (s.masked_columns || []).length === 0
        ? "<span class='hint'>整表原样保留</span>"
        : s.masked_columns.map((mc) => {
            const ruleLabel = RULE_LABELS_ZH[mc.rule] || RULE_MAP[mc.rule]?.label || mc.rule;
            return "<span class='result-rule-pill'>" +
              escapeHtml(mc.col_name) + " [" + escapeHtml(ruleLabel) + "] · " + mc.masked_count +
              "</span>";
          }).join("");
      tr.innerHTML =
        "<td><strong>" + escapeHtml(s.sheet_name) + "</strong></td>" +
        "<td>" + s.total_rows + "</td>" +
        "<td>" + s.data_rows + "</td>" +
        "<td>" + colsDesc + "</td>";
      tbody.appendChild(tr);
    }
  }

  $("backToStep2Btn").addEventListener("click", () => {
    if (state.inspectData) {
      goToStep(2);
    }
  });

  $("newFileBtn").addEventListener("click", async () => {
    const prevFileId = state.fileId;
    resetUploadUI();
    $("localPathInput").value = "";
    state.localPath = "";
    resetStep2();
    resetStep3();
    clearStatus("step1Status");
    $("inspectMeta").textContent = "支持单表或多工作表全量扫描";
    goToStep(1);
    await clearServerUpload(prevFileId);
  });

  $("downloadBtn").addEventListener("click", () => {
    if (!state.lastJobId) return;
    const url = "/api/download?job_id=" + encodeURIComponent(state.lastJobId) + "&token=" + encodeURIComponent(TOKEN);
    const a = document.createElement("a");
    a.href = url;
    a.download = "";
    document.body.appendChild(a);
    a.click();
    a.remove();
  });

  goToStep(1);
})();
</script>
</body>
</html>
"""
    return html.replace("__TOKEN__", token_json)


def _make_handler(state: _UISessionState) -> type[BaseHTTPRequestHandler]:
    """Create a request handler bound to the given _UISessionState."""

    class LocalUIHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            # Suppress default HTTP access logging so tokens/paths aren't leaked to stdout/stderr
            return

        def _send_bytes(
            self,
            status: int,
            content_type: str,
            body: bytes,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
            )
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send_bytes(status, "application/json; charset=utf-8", raw)

        def _send_error_json(self, status: int, exc: Exception | str) -> None:
            msg = exc if isinstance(exc, str) else rules.sanitize_error(exc)
            self._send_json(status, {"ok": False, "status": "error", "error": msg})

        def _require_header_token(self) -> bool:
            provided = self.headers.get("X-Local-Token", "")
            if not provided or not secrets.compare_digest(provided, state.token):
                self._send_error_json(HTTPStatus.FORBIDDEN, "Invalid or missing X-Local-Token")
                return False
            return True

        def _read_json_body(self) -> dict[str, Any]:
            raw_len = self.headers.get("Content-Length")
            if raw_len is None:
                raise ValueError("Missing Content-Length header")
            length = int(raw_len)
            if length <= 0 or length > 16 * 1024 * 1024:
                raise ValueError("Invalid JSON request body size")
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Request JSON payload must be an object")
            return data

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                html = _render_html(state.token).encode("utf-8")
                self._send_bytes(HTTPStatus.OK, "text/html; charset=utf-8", html)
                return

            if parsed.path == "/api/download":
                self._handle_download(parsed.query)
                return

            self._send_error_json(HTTPStatus.NOT_FOUND, "Endpoint not found")

        def do_POST(self) -> None:
            if not self._require_header_token():
                return

            parsed = urlparse(self.path)
            if parsed.path == "/api/upload":
                self._handle_upload(parsed.query)
                return
            if parsed.path == "/api/upload/clear":
                self._handle_upload_clear()
                return
            if parsed.path == "/api/inspect":
                self._handle_inspect()
                return
            if parsed.path == "/api/preview":
                self._handle_preview()
                return
            if parsed.path == "/api/apply":
                self._handle_apply()
                return

            self._send_error_json(HTTPStatus.NOT_FOUND, "Endpoint not found")

        def _handle_upload(self, query: str) -> None:
            try:
                qs = parse_qs(query, keep_blank_values=False)
                raw_filename = (qs.get("filename") or [""])[0]
                safe_name = _sanitize_upload_filename(raw_filename)

                raw_len = self.headers.get("Content-Length")
                if raw_len is None:
                    raise ValueError("Missing Content-Length header")
                content_length = int(raw_len)
                if content_length <= 0:
                    raise ValueError("Uploaded file is empty")

                file_id = uuid.uuid4().hex
                target_dir = state.uploads_dir / file_id
                target_dir.mkdir(parents=True, exist_ok=True)
                dest_path = target_dir / safe_name

                remaining = content_length
                written = 0
                try:
                    with open(dest_path, "wb") as f:
                        while remaining > 0:
                            chunk = self.rfile.read(min(_UPLOAD_CHUNK_SIZE, remaining))
                            if not chunk:
                                raise ValueError("Unexpected EOF while reading upload stream")
                            f.write(chunk)
                            written += len(chunk)
                            remaining -= len(chunk)
                except Exception:
                    shutil.rmtree(target_dir, ignore_errors=True)
                    raise

                state.register_upload(file_id, dest_path, safe_name, written)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "file_id": file_id,
                        "filename": safe_name,
                        "size": written,
                    },
                )
            except Exception as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, exc)

        def _handle_upload_clear(self) -> None:
            """Remove a previously uploaded temporary file and its session record."""
            try:
                body = self._read_json_body()
                file_id = str(body.get("file_id") or "").strip()
                if not file_id:
                    raise ValueError("'file_id' is required")

                info = state.remove_upload(file_id)
                cleared = False
                if info:
                    target_path = Path(info["path"]).resolve()
                    uploads_root = state.uploads_dir.resolve()
                    target_dir = target_path.parent
                    if target_dir.parent == uploads_root and target_dir.exists():
                        shutil.rmtree(target_dir, ignore_errors=True)
                    elif target_path.is_file() and uploads_root in target_path.parents:
                        target_path.unlink(missing_ok=True)
                    cleared = True

                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "cleared": cleared,
                        "file_id": file_id,
                    },
                )
            except Exception as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, exc)

        def _resolve_input_source(self, body: dict[str, Any]) -> tuple[str, bool]:
            """Resolve (input_path, is_local_path_mode) from request payload."""
            file_id = body.get("file_id")
            local_path = body.get("local_path")

            if file_id:
                info = state.get_upload(str(file_id))
                if not info:
                    raise FileNotFoundError("Uploaded file session not found or expired")
                p = Path(info["path"])
                if not p.is_file():
                    raise FileNotFoundError("Uploaded file no longer exists")
                return str(p), False

            if local_path:
                return _clean_local_path(str(local_path)), True

            raise ValueError("Either 'file_id' or 'local_path' must be provided")

        def _source_cache_key(self, body: dict[str, Any], input_path: str, is_local: bool) -> str:
            if not is_local:
                return f"file:{str(body.get('file_id') or '').strip()}"
            return f"local:{os.path.normcase(os.path.realpath(input_path))}"

        def _handle_inspect(self) -> None:
            try:
                body = self._read_json_body()
                input_path, is_local = self._resolve_input_source(body)
                source_key = self._source_cache_key(body, input_path, is_local)
                raw_sheet = body.get("sheet_name")
                sheet_name = str(raw_sheet).strip() if raw_sheet not in (None, "") else None
                chunk_size = int(body.get("chunk_size", engine.DEFAULT_INSPECT_CHUNK_SIZE))
                workers = body.get("workers")
                max_workers = int(workers) if workers is not None else None

                result = engine.inspect_file(
                    input_path=input_path,
                    sheet_name=sheet_name,
                    chunk_size=chunk_size,
                    max_workers=max_workers,
                )
                samples_by_sheet = engine.extract_column_samples(
                    input_path=input_path,
                    sheet_name=sheet_name,
                )
                state.set_column_samples(
                    source_key,
                    samples_by_sheet,
                    replace=(sheet_name is None),
                )
                # In upload mode, avoid echoing temp upload path
                if not is_local:
                    result["file"] = Path(input_path).name
                payload = {"ok": True, **result}
                self._send_json(HTTPStatus.OK, payload)
            except FileNotFoundError as exc:
                self._send_error_json(HTTPStatus.NOT_FOUND, exc)
            except Exception as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, exc)

        def _handle_preview(self) -> None:
            try:
                body = self._read_json_body()
                input_path, is_local = self._resolve_input_source(body)
                source_key = self._source_cache_key(body, input_path, is_local)

                raw_sheet = body.get("sheet_name")
                sheet_name = str(raw_sheet).strip() if raw_sheet not in (None, "") else None
                raw_salt = body.get("global_salt")
                global_salt = "" if raw_salt is None else str(raw_salt)

                columns_req = body.get("columns")
                if columns_req is not None and not isinstance(columns_req, dict):
                    raise ValueError("'columns' must be a JSON object")

                cached_sheets = state.get_column_samples(source_key, sheet_name=sheet_name)
                if cached_sheets is None:
                    extracted = engine.extract_column_samples(
                        input_path=input_path,
                        sheet_name=sheet_name,
                    )
                    state.set_column_samples(
                        source_key,
                        extracted,
                        replace=(sheet_name is None),
                    )
                    cached_sheets = state.get_column_samples(source_key, sheet_name=sheet_name) or {}

                if not cached_sheets:
                    raise ValueError(
                        f"Sheet '{sheet_name}' not found" if sheet_name else "No sheets found in file"
                    )

                target_sheet = sheet_name if sheet_name is not None else next(iter(cached_sheets))
                sheet_samples = cached_sheets.get(target_sheet)
                if sheet_samples is None:
                    raise ValueError(f"Sheet '{target_sheet}' not found")

                if columns_req:
                    target_columns = columns_req
                else:
                    target_columns = {col_name: {"rule": "none"} for col_name in sheet_samples}

                previews: dict[str, dict[str, Any]] = {}
                for col_name, raw_spec in target_columns.items():
                    col_key = str(col_name)
                    spec = raw_spec if isinstance(raw_spec, dict) else {}
                    rule_name = str(spec.get("rule") or "none").strip() or "none"
                    sensitive_type = spec.get("sensitive_type")
                    raw_params = spec.get("params")
                    params = dict(raw_params) if isinstance(raw_params, dict) else {}

                    if (
                        (
                            rule_name == "hash_sha256"
                            or (rule_name == "obfuscate" and params.get("mode") == "consistent")
                        )
                        and (params.get("salt") is None or params.get("salt") == "")
                        and global_salt
                    ):
                        params["salt"] = global_salt

                    raw_samples = sheet_samples.get(col_key, [])[:3]
                    try:
                        if rule_name == "regex_replace" and params.get("pattern"):
                            rules._compile_user_regex(str(params["pattern"]))

                        raw_clean_samples = [rules._to_clean_str(val) for val in raw_samples]
                        if rule_name == "none":
                            out_samples = raw_clean_samples
                            unchanged = False
                        else:
                            rule_spec = {
                                "rule": rule_name,
                                "sensitive_type": sensitive_type,
                                "params": params,
                            }
                            out_samples = [
                                rules._to_clean_str(rules.apply_rule(val, rule_spec))
                                for val in raw_samples
                            ]
                            unchanged = (
                                len(out_samples) > 0
                                and len(out_samples) == len(raw_clean_samples)
                                and all(
                                    after == before
                                    for after, before in zip(out_samples, raw_clean_samples)
                                )
                            )
                        previews[col_key] = {
                            "samples": out_samples,
                            "unchanged": unchanged,
                            "error": None,
                        }
                    except re.error:
                        previews[col_key] = {
                            "samples": [],
                            "unchanged": False,
                            "error": "正则格式有误，请检查语法",
                        }
                    except Exception as exc:
                        previews[col_key] = {
                            "samples": [],
                            "unchanged": False,
                            "error": rules.sanitize_error(exc),
                        }

                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "sheet_name": target_sheet,
                        "previews": previews,
                    },
                )
            except FileNotFoundError as exc:
                self._send_error_json(HTTPStatus.NOT_FOUND, exc)
            except Exception as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, exc)

        def _handle_apply(self) -> None:
            try:
                body = self._read_json_body()
                input_path, is_local = self._resolve_input_source(body)

                config = body.get("config")
                if not isinstance(config, dict):
                    raise ValueError("'config' must be a JSON object")

                workers_raw = body.get("workers")
                workers = int(workers_raw) if workers_raw is not None else None
                chunk_size = int(body.get("chunk_size", engine.DEFAULT_APPLY_CHUNK_SIZE))

                job_id = uuid.uuid4().hex
                if is_local:
                    requested_out = body.get("output_path")
                    output_arg = str(requested_out).strip() if requested_out else None
                else:
                    in_p = Path(input_path)
                    out_ext = ".csv" if in_p.suffix.lower() == ".csv" else ".xlsx"
                    job_dir = state.outputs_dir / job_id
                    job_dir.mkdir(parents=True, exist_ok=True)
                    output_arg = str(job_dir / f"{in_p.stem}_masked{out_ext}")

                result = engine.apply_masking(
                    input_path=input_path,
                    config=config,
                    output_path=output_arg,
                    workers=workers,
                    chunk_size=chunk_size,
                )

                out_file = Path(result["output_file"])
                state.register_job(job_id, out_file, out_file.name)

                payload: dict[str, Any] = {
                    "ok": True,
                    "job_id": job_id,
                    **result,
                }
                if is_local:
                    payload["output_path"] = str(out_file)
                else:
                    payload["input_file"] = Path(input_path).name
                    payload["output_file"] = out_file.name

                self._send_json(HTTPStatus.OK, payload)
            except FileNotFoundError as exc:
                self._send_error_json(HTTPStatus.NOT_FOUND, exc)
            except Exception as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, exc)

        def _handle_download(self, query: str) -> None:
            try:
                qs = parse_qs(query, keep_blank_values=False)
                q_token = (qs.get("token") or [""])[0]
                h_token = self.headers.get("X-Local-Token", "")
                provided = q_token or h_token
                if not provided or not secrets.compare_digest(provided, state.token):
                    self._send_error_json(HTTPStatus.FORBIDDEN, "Invalid or missing token")
                    return

                job_id = (qs.get("job_id") or [""])[0]
                if not job_id:
                    self._send_error_json(HTTPStatus.BAD_REQUEST, "Missing job_id parameter")
                    return

                job = state.get_job(job_id)
                if not job:
                    self._send_error_json(HTTPStatus.NOT_FOUND, "Download job not found")
                    return

                out_path = Path(job["output_path"])
                if not out_path.is_file():
                    self._send_error_json(HTTPStatus.NOT_FOUND, "Masked output file not found")
                    return

                file_size = out_path.stat().st_size
                filename = job["filename"]
                ext = out_path.suffix.lower()
                if ext == ".csv":
                    ctype = "text/csv; charset=utf-8"
                else:
                    ctype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

                ascii_fallback = "masked" + ext
                encoded_name = quote(filename, safe="")
                disp = f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded_name}"

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(file_size))
                self.send_header("Content-Disposition", disp)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()

                with open(out_path, "rb") as f:
                    while True:
                        chunk = f.read(_DOWNLOAD_CHUNK_SIZE)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            except BrokenPipeError:
                return
            except Exception as exc:
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, exc)

    return LocalUIHandler


class LocalMaskingServer:
    """Wrapper managing ThreadingHTTPServer lifecycle and temp session cleanup."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        session_dir: Path | None = None,
    ) -> None:
        if not is_loopback_host(host):
            raise ValueError(
                f"Refusing to bind non-loopback host '{host}'. Only loopback hosts (e.g. 127.0.0.1) are permitted."
            )
        if not (0 <= int(port) <= 65535):
            raise ValueError(f"Port must be between 0 and 65535, got {port}")

        self.host = host
        self.state = _UISessionState(session_dir=session_dir)

        class _BoundServer(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.httpd = _BoundServer((host, int(port)), _make_handler(self.state))
        actual_host, actual_port = self.httpd.server_address[:2]
        self.port = int(actual_port)
        display_host = f"[{actual_host}]" if ":" in str(actual_host) else str(actual_host)
        self.url = f"http://{display_host}:{self.port}/"

        atexit.register(self.state.cleanup)

    def serve_forever(self) -> None:
        try:
            self.httpd.serve_forever()
        finally:
            self.close()

    def close(self) -> None:
        try:
            self.httpd.server_close()
        finally:
            self.state.cleanup()


def run_ui(
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = True,
) -> int:
    """Start the offline local Web UI server and block until interrupted."""
    server = LocalMaskingServer(host=host, port=port)
    print(f"Local Excel/CSV Masking UI running at: {server.url}", flush=True)
    print("Press Ctrl+C to stop and clean up session temporary files.", flush=True)

    if open_browser:
        threading.Timer(0.25, lambda: webbrowser.open(server.url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down local UI and cleaning up temporary files...", flush=True)
        server.close()
    return 0
