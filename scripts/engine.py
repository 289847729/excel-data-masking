"""High-throughput streaming & multiprocessing masking engine for Excel and CSV.

Design highlights:
- Streaming reads via python-calamine (primary) with openpyxl/xlrd/csv fallbacks.
- Adaptive concurrency: single-process fast path for small tables (< 20,000 rows),
  bounded-inflight ProcessPoolExecutor for large tables (>= 20,000 rows).
- Zero-copy passthrough for unmasked columns and unconfigured sheets.
- Streaming writes via xlsxwriter (constant_memory=True) or openpyxl(write_only=True) / csv.
- Zero-plaintext invariant: raw cell values never enter stdout, stderr, or sanitized errors.
"""

from __future__ import annotations

import csv
import datetime as _dt
import math
import multiprocessing as mp
import os
import secrets
import sys
import time
from collections import deque
from concurrent.futures import Future, ProcessPoolExecutor
from pathlib import Path
from typing import Any, Iterator

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import rules

# ---------------------------------------------------------------------------
# Constants & format support
# ---------------------------------------------------------------------------

EXCEL_EXTENSIONS = {".xlsx", ".xlsm", ".xls", ".xlsb"}
CSV_EXTENSIONS = {".csv"}
SUPPORTED_EXTENSIONS = EXCEL_EXTENSIONS | CSV_EXTENSIONS

SMALL_TABLE_THRESHOLD = 20_000
DEFAULT_INSPECT_CHUNK_SIZE = 20_000
DEFAULT_APPLY_CHUNK_SIZE = 15_000
DEFAULT_MAX_WORKERS = 8
# Windows ProcessPoolExecutor waits on at most 61 handles (WAIT_OBJECTS limit).
WINDOWS_SAFE_MAX_WORKERS = 60

_SEMANTIC_TYPES = {"person_name", "address", "secret"}


# ---------------------------------------------------------------------------
# Value normalization & CSV inference helpers
# ---------------------------------------------------------------------------


def _normalize_cell(value: Any) -> Any:
    """Normalize backend-specific cell quirks (e.g., integer floats from calamine)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        # Excel stores numbers as IEEE-754 floats; convert exact integer values
        # below 2^53 back to int so phone numbers / IDs aren't formatted as "...0".
        if value.is_integer() and abs(value) < 9_007_199_254_740_992:
            return int(value)
        return value
    if isinstance(value, str):
        if value == "":
            return None
        return value
    return value


def _is_empty_cell(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == "":
        return True
    return False


def _cell_value_kind(value: Any) -> tuple[str, int]:
    """Return (kind, display_length) for a normalized non-empty cell."""
    if isinstance(value, bool):
        s = "true" if value else "false"
        return "bool", len(s)
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return "date", len(value.isoformat())
    if isinstance(value, (int, float)):
        return "number", len(str(value))
    s = str(value).strip()
    return "text", len(s)


def _cell_to_detect_str(value: Any) -> str:
    """Convert normalized cell to string for regex/validator inspection."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer() and abs(value) < 9_007_199_254_740_992:
            return str(int(value))
        return str(value)
    return str(value).strip()


def _sanitize_write_cell(value: Any) -> Any:
    """Ensure a cell value is safe for xlsxwriter constant_memory output."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return value
    if isinstance(value, _dt.datetime):
        # xlsxwriter does not accept timezone-aware datetimes
        return value.replace(tzinfo=None) if value.tzinfo is not None else value
    if isinstance(value, _dt.timedelta):
        return str(value)
    if isinstance(value, str):
        if len(value) > 32767:
            return value[:32767]
        return value
    return value


def _resolve_workers(requested: int | None) -> int:
    cpu = os.cpu_count() or 4
    hard_cap = min(WINDOWS_SAFE_MAX_WORKERS, max(1, cpu))
    default_cap = min(DEFAULT_MAX_WORKERS, hard_cap)
    if requested is None or requested <= 0:
        return default_cap
    return min(max(1, int(requested)), hard_cap)


def _detect_csv_encoding(path: str) -> str:
    """Detect CSV text encoding among utf-8-sig, utf-8, and gb18030."""
    import codecs

    with open(path, "rb") as f:
        head = f.read(65536)
        if head.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        dec = codecs.getincrementaldecoder("utf-8")(errors="strict")
        try:
            dec.decode(head, final=False)
            scanned = len(head)
            while scanned < 4 * 1024 * 1024:
                chunk = f.read(65536)
                if not chunk:
                    dec.decode(b"", final=True)
                    return "utf-8"
                dec.decode(chunk, final=False)
                scanned += len(chunk)
            return "utf-8"
        except UnicodeDecodeError:
            return "gb18030"


def _normalize_headers(raw_header: list[Any], width: int) -> list[str]:
    """Produce non-empty unique-preserving display column names for metadata/config matching."""
    names: list[str] = []
    for idx in range(width):
        val = raw_header[idx] if idx < len(raw_header) else None
        if val is None or str(val).strip() == "":
            names.append(f"col_{idx + 1}")
        else:
            names.append(str(val).strip())
    return names


# ---------------------------------------------------------------------------
# Streaming Readers (Excel via calamine -> openpyxl/xlrd; CSV via csv.reader)
# ---------------------------------------------------------------------------


def _iter_calamine_chunks(
    path: str,
    sheet_filter: str | None,
    chunk_size: int,
) -> Iterator[tuple[str, int | None, Iterator[list[list[Any]]]]]:
    """Yield (sheet_name, estimated_rows, chunk_iterator) using python-calamine."""
    import python_calamine  # type: ignore

    wb = python_calamine.CalamineWorkbook.from_path(path)
    try:
        sheet_names = list(wb.sheet_names)
        if sheet_filter is not None:
            if sheet_filter not in sheet_names:
                raise ValueError(f"Sheet not found: {sheet_filter}")
            sheet_names = [sheet_filter]

        for sname in sheet_names:
            sheet = wb.get_sheet_by_name(sname)
            est_rows = getattr(sheet, "total_height", None)

            def _row_chunks(sh=sheet) -> Iterator[list[list[Any]]]:
                buf: list[list[Any]] = []
                for row in sh.iter_rows():
                    buf.append([_normalize_cell(c) for c in row])
                    if len(buf) >= chunk_size:
                        yield buf
                        buf = []
                if buf:
                    yield buf

            yield sname, est_rows, _row_chunks()
    finally:
        close_fn = getattr(wb, "close", None)
        if callable(close_fn):
            close_fn()


def _iter_openpyxl_chunks(
    path: str,
    sheet_filter: str | None,
    chunk_size: int,
) -> Iterator[tuple[str, int | None, Iterator[list[list[Any]]]]]:
    """Fallback streaming reader for .xlsx/.xlsm using openpyxl read_only=True."""
    import openpyxl  # type: ignore

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        sheet_names = list(wb.sheetnames)
        if sheet_filter is not None:
            if sheet_filter not in sheet_names:
                raise ValueError(f"Sheet not found: {sheet_filter}")
            sheet_names = [sheet_filter]

        for sname in sheet_names:
            ws = wb[sname]
            est_rows = ws.max_row if isinstance(ws.max_row, int) and ws.max_row > 0 else None

            def _row_chunks(worksheet=ws) -> Iterator[list[list[Any]]]:
                buf: list[list[Any]] = []
                for row in worksheet.iter_rows(values_only=True):
                    buf.append([_normalize_cell(c) for c in row])
                    if len(buf) >= chunk_size:
                        yield buf
                        buf = []
                if buf:
                    yield buf

            yield sname, est_rows, _row_chunks()
    finally:
        wb.close()


def _iter_xlrd_chunks(
    path: str,
    sheet_filter: str | None,
    chunk_size: int,
) -> Iterator[tuple[str, int | None, Iterator[list[list[Any]]]]]:
    """Fallback reader for legacy .xls files via xlrd."""
    import xlrd  # type: ignore

    wb = xlrd.open_workbook(path, on_demand=True)
    try:
        sheet_names = list(wb.sheet_names())
        if sheet_filter is not None:
            if sheet_filter not in sheet_names:
                raise ValueError(f"Sheet not found: {sheet_filter}")
            sheet_names = [sheet_filter]

        for sname in sheet_names:
            sh = wb.sheet_by_name(sname)
            est_rows = sh.nrows

            def _row_chunks(sheet=sh, datemode=wb.datemode) -> Iterator[list[list[Any]]]:
                buf: list[list[Any]] = []
                for r in range(sheet.nrows):
                    row_vals: list[Any] = []
                    for c in range(sheet.ncols):
                        cell = sheet.cell(r, c)
                        ctype = cell.ctype
                        val = cell.value
                        if ctype in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK):
                            row_vals.append(None)
                        elif ctype == xlrd.XL_CELL_DATE:
                            try:
                                row_vals.append(xlrd.xldate_as_datetime(val, datemode))
                            except Exception:
                                row_vals.append(val)
                        elif ctype == xlrd.XL_CELL_BOOLEAN:
                            row_vals.append(bool(val))
                        else:
                            row_vals.append(_normalize_cell(val))
                    buf.append(row_vals)
                    if len(buf) >= chunk_size:
                        yield buf
                        buf = []
                if buf:
                    yield buf

            yield sname, est_rows, _row_chunks()
    finally:
        wb.release_resources()


def _iter_csv_chunks(
    path: str,
    chunk_size: int,
) -> tuple[str, int | None, Iterator[list[list[Any]]], str]:
    """Streaming CSV reader with encoding auto-detection."""
    encoding = _detect_csv_encoding(path)

    def _row_chunks() -> Iterator[list[list[Any]]]:
        with open(path, "r", encoding=encoding, errors="replace", newline="") as f:
            reader = csv.reader(f)
            buf: list[list[Any]] = []
            for row in reader:
                buf.append([None if c == "" else c for c in row])
                if len(buf) >= chunk_size:
                    yield buf
                    buf = []
            if buf:
                yield buf

    # Rough estimate from file size so small CSVs stay single-process
    file_size = os.path.getsize(path)
    est_rows = max(1, file_size // 40) if file_size > 0 else 0
    return "CSV", est_rows, _row_chunks(), encoding


def _open_sheet_reader(
    path: str,
    sheet_filter: str | None,
    chunk_size: int,
) -> tuple[str, str, Iterator[tuple[str, int | None, Iterator[list[list[Any]]]]]]:
    """Return (file_format, read_engine_name, sheet_iterator)."""
    ext = Path(path).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file extension: {ext}")

    if ext in CSV_EXTENSIONS:
        if sheet_filter is not None and sheet_filter not in ("CSV", "Sheet1"):
            raise ValueError(f"CSV files do not contain sheet: {sheet_filter}")
        sname, est_rows, chunk_iter, enc = _iter_csv_chunks(path, chunk_size)

        def _csv_gen() -> Iterator[tuple[str, int | None, Iterator[list[list[Any]]]]]:
            yield sname, est_rows, chunk_iter

        return "csv", f"csv({enc})", _csv_gen()

    # Excel formats: prefer python-calamine
    try:
        import python_calamine  # noqa: F401

        return ext.lstrip("."), "calamine", _iter_calamine_chunks(path, sheet_filter, chunk_size)
    except ImportError:
        pass
    except Exception:
        # If calamine fails to open a specific legacy file, try native fallback
        if ext == ".xls":
            return ext.lstrip("."), "xlrd", _iter_xlrd_chunks(path, sheet_filter, chunk_size)
        if ext in (".xlsx", ".xlsm"):
            return ext.lstrip("."), "openpyxl", _iter_openpyxl_chunks(path, sheet_filter, chunk_size)
        raise

    if ext == ".xls":
        return ext.lstrip("."), "xlrd", _iter_xlrd_chunks(path, sheet_filter, chunk_size)
    if ext in (".xlsx", ".xlsm"):
        return ext.lstrip("."), "openpyxl", _iter_openpyxl_chunks(path, sheet_filter, chunk_size)
    raise RuntimeError("python-calamine is required to read .xlsb files")


# ---------------------------------------------------------------------------
# Inspect workers (stateless, pickle-safe, zero-plaintext previews)
# ---------------------------------------------------------------------------


def _inspect_chunk_worker(
    rows: list[list[Any]],
    col_count: int,
    semantic_targets: list[tuple[int, str]],
) -> dict[str, Any]:
    """Scan a chunk of data rows and return aggregated metadata + masked previews only."""
    non_null = [0] * col_count
    kind_sets: list[set[str]] = [set() for _ in range(col_count)]
    min_lens: list[int | None] = [None] * col_count
    max_lens = [0] * col_count
    type_hits: list[dict[str, int]] = [{} for _ in range(col_count)]
    masked_samples: list[dict[str, list[str]]] = [{} for _ in range(col_count)]
    inline_hits = [False] * col_count

    sem_map: dict[int, str] = dict(semantic_targets)
    semantic_samples: dict[int, list[str]] = {idx: [] for idx in sem_map}

    for row in rows:
        rlen = len(row)
        limit = col_count if rlen >= col_count else rlen
        for idx in range(limit):
            val = row[idx]
            if _is_empty_cell(val):
                continue

            non_null[idx] += 1
            kind, clen = _cell_value_kind(val)
            kind_sets[idx].add(kind)
            if min_lens[idx] is None or clen < min_lens[idx]:
                min_lens[idx] = clen
            if clen > max_lens[idx]:
                max_lens[idx] = clen

            # Semantic column masked preview collection (up to 3 distinct masked values)
            if idx in sem_map and len(semantic_samples[idx]) < 3:
                stype = sem_map[idx]
                default_rule = rules.SENSITIVE_TYPES[stype]["default_rule"]
                masked_val = str(
                    rules.apply_rule(
                        val,
                        {"rule": default_rule, "sensitive_type": stype, "params": {}},
                    )
                )
                if masked_val and masked_val not in semantic_samples[idx]:
                    semantic_samples[idx].append(masked_val)

            detect_str = _cell_to_detect_str(val)
            hits = rules.detect_value_types(detect_str)
            if hits:
                col_hits = type_hits[idx]
                col_samples = masked_samples[idx]
                for stype in hits:
                    col_hits[stype] = col_hits.get(stype, 0) + 1
                    sample_list = col_samples.get(stype)
                    if sample_list is None:
                        sample_list = []
                        col_samples[stype] = sample_list
                    if len(sample_list) < 3:
                        default_rule = rules.SENSITIVE_TYPES[stype]["default_rule"]
                        masked_val = str(
                            rules.apply_rule(
                                val,
                                {"rule": default_rule, "sensitive_type": stype, "params": {}},
                            )
                        )
                        if masked_val and masked_val not in sample_list:
                            sample_list.append(masked_val)
            elif not inline_hits[idx] and kind == "text" and clen >= 11:
                if rules.has_inline_sensitive(detect_str):
                    inline_hits[idx] = True

    return {
        "row_count": len(rows),
        "non_null": non_null,
        "kind_sets": [list(s) for s in kind_sets],
        "min_lens": min_lens,
        "max_lens": max_lens,
        "type_hits": type_hits,
        "masked_samples": masked_samples,
        "inline_hits": inline_hits,
        "semantic_samples": semantic_samples,
    }


def _merge_inspect_stats(
    acc: dict[str, Any],
    part: dict[str, Any],
    col_count: int,
) -> None:
    acc["row_count"] += part["row_count"]
    for idx in range(col_count):
        acc["non_null"][idx] += part["non_null"][idx]
        acc["kind_sets"][idx].update(part["kind_sets"][idx])
        pmin = part["min_lens"][idx]
        if pmin is not None:
            cmin = acc["min_lens"][idx]
            if cmin is None or pmin < cmin:
                acc["min_lens"][idx] = pmin
        if part["max_lens"][idx] > acc["max_lens"][idx]:
            acc["max_lens"][idx] = part["max_lens"][idx]
        for stype, cnt in part["type_hits"][idx].items():
            acc["type_hits"][idx][stype] = acc["type_hits"][idx].get(stype, 0) + cnt
        for stype, samples in part["masked_samples"][idx].items():
            target = acc["masked_samples"][idx].setdefault(stype, [])
            if len(target) < 3:
                for s in samples:
                    if s not in target:
                        target.append(s)
                        if len(target) >= 3:
                            break
        if part["inline_hits"][idx]:
            acc["inline_hits"][idx] = True

    for idx, samples in part["semantic_samples"].items():
        target = acc["semantic_samples"].setdefault(idx, [])
        if len(target) < 3:
            for s in samples:
                if s not in target:
                    target.append(s)
                    if len(target) >= 3:
                        break


def _resolve_value_kind(kinds: set[str]) -> str:
    if not kinds:
        return "text"
    if len(kinds) == 1:
        return next(iter(kinds))
    return "mixed"


def inspect_file(
    input_path: str,
    sheet_name: str | None = None,
    chunk_size: int = DEFAULT_INSPECT_CHUNK_SIZE,
    max_workers: int | None = None,
) -> dict[str, Any]:
    """Full-column streaming inspection with zero plaintext output."""
    t0 = time.perf_counter()
    resolved_path = os.path.realpath(input_path)
    if not os.path.isfile(resolved_path):
        raise FileNotFoundError(f"Input file not found: {Path(input_path).name}")

    chunk_size = max(100, int(chunk_size))
    workers = _resolve_workers(max_workers)
    file_fmt, read_engine, sheet_iter = _open_sheet_reader(resolved_path, sheet_name, chunk_size)

    sheets_out: list[dict[str, Any]] = []
    pool: ProcessPoolExecutor | None = None

    try:
        for sname, est_rows, chunks in sheet_iter:
            headers: list[str] | None = None
            col_count = 0
            semantic_targets: list[tuple[int, str]] = []
            acc: dict[str, Any] | None = None
            pending: deque[Future[dict[str, Any]]] = deque()

            use_pool_hint = est_rows is not None and est_rows >= SMALL_TABLE_THRESHOLD
            max_inflight = workers * 2

            for chunk in chunks:
                if not chunk:
                    continue
                if headers is None:
                    raw_header = chunk[0]
                    col_count = len(raw_header)
                    headers = _normalize_headers(raw_header, col_count)
                    for idx, cname in enumerate(headers):
                        hscores = rules.score_header(cname)
                        best_sem = max(
                            ((st, hscores.get(st, 0.0)) for st in _SEMANTIC_TYPES),
                            key=lambda kv: kv[1],
                        )
                        if best_sem[1] >= 0.75:
                            semantic_targets.append((idx, best_sem[0]))

                    acc = {
                        "row_count": 0,
                        "non_null": [0] * col_count,
                        "kind_sets": [set() for _ in range(col_count)],
                        "min_lens": [None] * col_count,
                        "max_lens": [0] * col_count,
                        "type_hits": [{} for _ in range(col_count)],
                        "masked_samples": [{} for _ in range(col_count)],
                        "inline_hits": [False] * col_count,
                        "semantic_samples": {},
                    }
                    data_rows = chunk[1:]
                else:
                    data_rows = chunk

                if not data_rows:
                    continue

                # If chunk is full and est_rows wasn't tiny, allow pool for large streams
                if not use_pool_hint and est_rows is None and len(data_rows) >= chunk_size:
                    use_pool_hint = True

                if use_pool_hint and workers > 1:
                    if pool is None:
                        pool = ProcessPoolExecutor(
                            max_workers=workers,
                            mp_context=mp.get_context("spawn"),
                        )
                    pending.append(
                        pool.submit(_inspect_chunk_worker, data_rows, col_count, semantic_targets)
                    )
                    if len(pending) >= max_inflight:
                        _merge_inspect_stats(acc, pending.popleft().result(), col_count)
                else:
                    part = _inspect_chunk_worker(data_rows, col_count, semantic_targets)
                    _merge_inspect_stats(acc, part, col_count)

            while pending:
                assert acc is not None
                _merge_inspect_stats(acc, pending.popleft().result(), col_count)

            if headers is None or acc is None:
                sheets_out.append(
                    {
                        "sheet_name": sname,
                        "total_rows": 0,
                        "data_rows": 0,
                        "column_count": 0,
                        "columns": [],
                    }
                )
                continue

            cols_out: list[dict[str, Any]] = []
            for idx, cname in enumerate(headers):
                vkind = _resolve_value_kind(acc["kind_sets"][idx])
                min_len = acc["min_lens"][idx] if acc["min_lens"][idx] is not None else 0
                max_len = acc["max_lens"][idx]
                rec = rules.recommend_column(
                    col_name=cname,
                    non_null_count=acc["non_null"][idx],
                    type_hits=acc["type_hits"][idx],
                    sample_masked=acc["masked_samples"][idx],
                    value_kind=vkind,
                    min_len=min_len,
                    max_len=max_len,
                )
                if rec["is_sensitive"]:
                    stype = rec["sensitive_type"]
                    if not rec["masked_previews"] and idx in acc["semantic_samples"]:
                        rec["masked_previews"] = list(acc["semantic_samples"][idx])[:3]
                else:
                    # Enforce zero-plaintext invariant defensively
                    rec["masked_previews"] = []
                    if acc["inline_hits"][idx]:
                        rec["inline_hint"] = True

                rec["col_index"] = idx
                cols_out.append(rec)

            data_row_count = acc["row_count"]
            sheets_out.append(
                {
                    "sheet_name": sname,
                    "total_rows": data_row_count + 1,
                    "data_rows": data_row_count,
                    "column_count": col_count,
                    "columns": cols_out,
                }
            )
    finally:
        close_iter = getattr(sheet_iter, "close", None)
        if callable(close_iter):
            close_iter()
        if pool is not None:
            pool.shutdown(wait=True)

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    return {
        "status": "ok",
        "command": "inspect",
        "file": str(Path(input_path)),
        "format": file_fmt,
        "engine_used": read_engine,
        "elapsed_ms": elapsed_ms,
        "sheets": sheets_out,
    }


def extract_column_samples(
    input_path: str | Path,
    sheet_name: str | None = None,
    max_samples: int = 3,
    max_scan_rows: int = 5000,
) -> dict[str, dict[str, list[Any]]]:
    """Stream-scan headers and up to `max_scan_rows` data rows to collect raw unique samples.

    Intended strictly for local Web UI live previews; never exposed to CLI/model outputs.
    Stops scanning a sheet early as soon as every column reaches `max_samples`.
    """
    raw_path = os.fspath(input_path)
    resolved_path = os.path.realpath(raw_path)
    if not os.path.isfile(resolved_path):
        raise FileNotFoundError(f"Input file not found: {Path(raw_path).name}")

    sample_limit = max(0, int(max_samples))
    row_limit = max(0, int(max_scan_rows))
    chunk_size = min(128, max(16, row_limit + 1))

    _file_fmt, _read_engine, sheet_iter = _open_sheet_reader(
        resolved_path, sheet_name, chunk_size
    )

    result: dict[str, dict[str, list[Any]]] = {}
    try:
        for sname, _est_rows, chunks in sheet_iter:
            headers: list[str] | None = None
            col_samples: list[list[Any]] = []
            col_seen: list[set[str]] = []
            remaining_cols: set[int] = set()
            scanned_rows = 0

            try:
                for chunk in chunks:
                    if not chunk:
                        continue

                    if headers is None:
                        raw_header = chunk[0]
                        col_count = len(raw_header)
                        headers = _normalize_headers(raw_header, col_count)
                        if col_count == 0:
                            break
                        col_samples = [[] for _ in range(col_count)]
                        col_seen = [set() for _ in range(col_count)]
                        if sample_limit == 0 or row_limit == 0:
                            break
                        remaining_cols = set(range(col_count))
                        data_rows = chunk[1:]
                    else:
                        data_rows = chunk

                    for row in data_rows:
                        if scanned_rows >= row_limit:
                            break
                        scanned_rows += 1
                        rlen = len(row)
                        for idx in tuple(remaining_cols):
                            if idx >= rlen:
                                continue
                            val = row[idx]
                            if _is_empty_cell(val):
                                continue
                            dedup_key = str(val).strip()
                            if dedup_key in col_seen[idx]:
                                continue
                            col_seen[idx].add(dedup_key)
                            col_samples[idx].append(val)
                            if len(col_samples[idx]) >= sample_limit:
                                remaining_cols.discard(idx)
                        if not remaining_cols:
                            break

                    if not remaining_cols or scanned_rows >= row_limit:
                        break
            finally:
                close_chunks = getattr(chunks, "close", None)
                if callable(close_chunks):
                    close_chunks()

            sheet_dict: dict[str, list[Any]] = {}
            if headers:
                for idx, cname in enumerate(headers):
                    if cname not in sheet_dict:
                        sheet_dict[cname] = col_samples[idx]
                    elif sample_limit > 0 and len(sheet_dict[cname]) < sample_limit:
                        existing_keys = {str(v).strip() for v in sheet_dict[cname]}
                        for v in col_samples[idx]:
                            key = str(v).strip()
                            if key not in existing_keys:
                                existing_keys.add(key)
                                sheet_dict[cname].append(v)
                                if len(sheet_dict[cname]) >= sample_limit:
                                    break
            result[sname] = sheet_dict
    finally:
        close_iter = getattr(sheet_iter, "close", None)
        if callable(close_iter):
            close_iter()

    return result


# ---------------------------------------------------------------------------
# Apply workers (stateless, column-slice only to minimize IPC overhead)
# ---------------------------------------------------------------------------


def _mask_columns_worker(
    col_slices: list[list[Any]],
    specs: list[dict[str, Any]],
) -> tuple[list[list[Any]], list[int]]:
    """Mask only configured columns (column-oriented slices) and return masked slices + counts."""
    counts: list[int] = []
    out_slices: list[list[Any]] = []
    for col_vals, spec in zip(col_slices, specs):
        rule = spec.get("rule", "none")
        masked_col: list[Any] = []
        changed = 0
        for val in col_vals:
            if val is None or (isinstance(val, str) and val.strip() == ""):
                masked_col.append(val)
                continue
            new_val = rules.apply_rule(val, spec)
            masked_col.append(new_val)
            if rule != "none":
                changed += 1
        out_slices.append(masked_col)
        counts.append(changed)
    return out_slices, counts


def _prepare_sheet_specs(
    headers: list[str],
    sheet_name: str,
    config: dict[str, Any],
    effective_global_salt: str | None,
) -> tuple[list[tuple[int, str, dict[str, Any]]], bool]:
    """Resolve active (non-none) column specs for a sheet.

    Sheet-level config (`sheets.<name>.columns.<col>`) overrides top-level `columns.<col>`.
    """
    global_cols: dict[str, Any] = config.get("columns") or {}
    sheets_cfg: dict[str, Any] = config.get("sheets") or {}
    sheet_cols: dict[str, Any] = (sheets_cfg.get(sheet_name) or {}).get("columns") or {}

    active: list[tuple[int, str, dict[str, Any]]] = []
    for idx, cname in enumerate(headers):
        raw_spec = None
        if cname in sheet_cols:
            raw_spec = sheet_cols[cname]
        elif cname in global_cols:
            raw_spec = global_cols[cname]

        if not raw_spec:
            continue

        rule_name = str(raw_spec.get("rule", "none"))
        if rule_name not in rules.RULE_TYPES:
            raise ValueError(f"Unsupported masking rule: {rule_name}")
        if rule_name == "none":
            continue

        params = dict(raw_spec.get("params") or {})
        if rule_name == "hash_sha256":
            col_salt = params.get("salt")
            if (col_salt is None or col_salt == "") and effective_global_salt:
                params["global_salt"] = effective_global_salt

        spec = {
            "rule": rule_name,
            "sensitive_type": raw_spec.get("sensitive_type"),
            "params": params,
        }
        active.append((idx, cname, spec))

    return active, (len(active) == 0)


def _resolve_salt_policy(config: dict[str, Any]) -> tuple[str | None, bool, str]:
    """Determine salt injection policy for hash_sha256 rules without exposing raw salt."""
    has_hash_rule = False
    needs_global_salt = False

    def _scan_cols(cols_dict: dict[str, Any]) -> None:
        nonlocal has_hash_rule, needs_global_salt
        for spec in (cols_dict or {}).values():
            if isinstance(spec, dict) and spec.get("rule") == "hash_sha256":
                has_hash_rule = True
                params = spec.get("params") or {}
                if not params.get("salt"):
                    needs_global_salt = True

    _scan_cols(config.get("columns") or {})
    for s_cfg in (config.get("sheets") or {}).values():
        if isinstance(s_cfg, dict):
            _scan_cols(s_cfg.get("columns") or {})

    if not has_hash_rule:
        return None, False, "not_needed"

    explicit_global = config.get("global_salt")
    allow_unsalted = bool(config.get("allow_unsalted", False))

    if explicit_global is not None and str(explicit_global) != "":
        return str(explicit_global), True, "explicit"
    if not needs_global_salt:
        return None, True, "column_explicit"
    if allow_unsalted:
        return None, False, "unsalted"

    # Auto-generate an ephemeral cryptographic salt for this execution run
    return secrets.token_hex(16), True, "generated_ephemeral"


# ---------------------------------------------------------------------------
# Streaming Writers
# ---------------------------------------------------------------------------


class _StreamingWriter:
    """Unified streaming writer for .xlsx (xlsxwriter -> openpyxl fallback) and .csv."""

    def __init__(self, out_path: str, is_csv: bool) -> None:
        self.out_path = out_path
        self.is_csv = is_csv
        self.backend = ""
        self._wb: Any = None
        self._ws: Any = None
        self._row_idx = 0
        self._csv_file: Any = None
        self._csv_writer: Any = None

        if is_csv:
            self._csv_file = open(out_path, "w", encoding="utf-8-sig", newline="")
            self._csv_writer = csv.writer(self._csv_file)
            self.backend = "csv(utf-8-sig)"
        else:
            try:
                import xlsxwriter  # type: ignore

                self._wb = xlsxwriter.Workbook(
                    out_path,
                    {
                        "constant_memory": True,
                        "strings_to_urls": False,
                        "strings_to_formulas": False,
                        "strings_to_numbers": False,
                        "default_date_format": "yyyy-mm-dd",
                    },
                )
                self.backend = "xlsxwriter"
            except ImportError:
                import openpyxl  # type: ignore

                self._wb = openpyxl.Workbook(write_only=True)
                self.backend = "openpyxl"

    def start_sheet(self, sheet_name: str) -> None:
        if self.is_csv:
            return
        self._row_idx = 0
        safe_title = (sheet_name or "Sheet1")[:31]
        if self.backend == "xlsxwriter":
            self._ws = self._wb.add_worksheet(safe_title)
        else:
            self._ws = self._wb.create_sheet(title=safe_title)

    def write_rows(self, rows: list[list[Any]]) -> None:
        if self.is_csv:
            self._csv_writer.writerows(
                ["" if c is None else c for c in row] for row in rows
            )
            return

        if self.backend == "xlsxwriter":
            ws = self._ws
            r_idx = self._row_idx
            for row in rows:
                ws.write_row(r_idx, 0, [_sanitize_write_cell(c) for c in row])
                r_idx += 1
            self._row_idx = r_idx
        else:
            ws = self._ws
            for row in rows:
                ws.append([_sanitize_write_cell(c) for c in row])

    def close(self) -> None:
        if self.is_csv:
            if self._csv_file is not None:
                self._csv_file.close()
                self._csv_file = None
        elif self._wb is not None:
            self._wb.close()
            self._wb = None


def resolve_output_path(input_path: str, output_path: str | None) -> tuple[str, bool]:
    """Compute safe output path and enforce strict no-overwrite protection."""
    in_norm = os.path.normcase(os.path.realpath(input_path))
    in_p = Path(input_path)
    in_ext = in_p.suffix.lower()

    if in_ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported input extension: {in_ext}")

    upgraded_from_xls = in_ext in {".xls", ".xlsm", ".xlsb"}

    if output_path is None or str(output_path).strip() == "":
        target_ext = ".csv" if in_ext == ".csv" else ".xlsx"
        computed = str(in_p.with_name(f"{in_p.stem}_masked{target_ext}"))
    else:
        computed = str(output_path)

    out_norm = os.path.normcase(os.path.realpath(computed))
    if in_norm == out_norm:
        raise ValueError("Refusing to overwrite input file: output path resolves to input path")

    return computed, upgraded_from_xls


def apply_masking(
    input_path: str,
    config: dict[str, Any],
    output_path: str | None = None,
    workers: int | None = None,
    chunk_size: int = DEFAULT_APPLY_CHUNK_SIZE,
) -> dict[str, Any]:
    """Execute streaming + bounded multiprocessing masking and write output file."""
    t0 = time.perf_counter()
    in_real = os.path.realpath(input_path)
    if not os.path.isfile(in_real):
        raise FileNotFoundError(f"Input file not found: {Path(input_path).name}")

    target_output, upgraded_from_xls = resolve_output_path(input_path, output_path)
    out_parent = Path(target_output).resolve().parent
    out_parent.mkdir(parents=True, exist_ok=True)

    out_ext = Path(target_output).suffix.lower()
    is_csv_out = out_ext == ".csv"
    if not is_csv_out and out_ext != ".xlsx":
        raise ValueError("Output file extension must be .xlsx (or .csv for CSV input)")

    # Write to a temporary sibling file first, then atomically replace target_output
    safe_stem = Path(target_output).stem[:40] or "masked"
    tmp_output = str(
        out_parent / f".{safe_stem}.tmp.{os.getpid()}{out_ext}"
    )

    chunk_size = max(100, int(chunk_size))
    eff_workers = _resolve_workers(workers)
    effective_global_salt, used_salt, salt_mode = _resolve_salt_policy(config)

    file_fmt, read_engine, sheet_iter = _open_sheet_reader(in_real, None, chunk_size)
    writer = _StreamingWriter(tmp_output, is_csv=is_csv_out)
    pool: ProcessPoolExecutor | None = None

    total_rows_processed = 0
    total_cells_masked = 0
    sheet_reports: list[dict[str, Any]] = []

    try:
        max_inflight = eff_workers * 2

        for sname, est_rows, chunks in sheet_iter:
            writer.start_sheet(sname)
            headers: list[str] | None = None
            active: list[tuple[int, str, dict[str, Any]]] = []
            active_indices: list[int] = []
            active_specs: list[dict[str, Any]] = []
            passthrough_only = True
            col_counts: list[int] = []
            sheet_data_rows = 0
            sheet_total_rows = 0

            use_pool_hint = est_rows is not None and est_rows >= SMALL_TABLE_THRESHOLD
            pending: deque[tuple[list[list[Any]], Future[tuple[list[list[Any]], list[int]]]]] = deque()

            def _drain_one() -> None:
                nonlocal total_cells_masked
                chunk_rows, fut = pending.popleft()
                out_slices, counts = fut.result()
                for i, c_idx in enumerate(active_indices):
                    masked_col = out_slices[i]
                    for r_i, val in enumerate(masked_col):
                        if c_idx < len(chunk_rows[r_i]):
                            chunk_rows[r_i][c_idx] = val
                for i, cnt in enumerate(counts):
                    col_counts[i] += cnt
                    total_cells_masked += cnt
                writer.write_rows(chunk_rows)

            for chunk in chunks:
                if not chunk:
                    continue

                if headers is None:
                    raw_header = chunk[0]
                    headers = _normalize_headers(raw_header, len(raw_header))
                    active, passthrough_only = _prepare_sheet_specs(
                        headers, sname, config, effective_global_salt
                    )
                    active_indices = [item[0] for item in active]
                    active_specs = [item[2] for item in active]
                    col_counts = [0] * len(active)

                    # Write header unchanged
                    writer.write_rows([raw_header])
                    sheet_total_rows += 1
                    data_rows = chunk[1:]
                else:
                    data_rows = chunk

                if not data_rows:
                    continue

                sheet_data_rows += len(data_rows)
                sheet_total_rows += len(data_rows)

                if passthrough_only:
                    writer.write_rows(data_rows)
                    continue

                if not use_pool_hint and est_rows is None and len(data_rows) >= chunk_size:
                    use_pool_hint = True

                # Extract only active columns to minimize IPC serialization
                col_slices = [
                    [row[c_idx] if c_idx < len(row) else None for row in data_rows]
                    for c_idx in active_indices
                ]

                if use_pool_hint and eff_workers > 1:
                    if pool is None:
                        pool = ProcessPoolExecutor(
                            max_workers=eff_workers,
                            mp_context=mp.get_context("spawn"),
                        )
                    fut = pool.submit(_mask_columns_worker, col_slices, active_specs)
                    pending.append((data_rows, fut))
                    if len(pending) >= max_inflight:
                        _drain_one()
                else:
                    out_slices, counts = _mask_columns_worker(col_slices, active_specs)
                    for i, c_idx in enumerate(active_indices):
                        masked_col = out_slices[i]
                        for r_i, val in enumerate(masked_col):
                            if c_idx < len(data_rows[r_i]):
                                data_rows[r_i][c_idx] = val
                    for i, cnt in enumerate(counts):
                        col_counts[i] += cnt
                        total_cells_masked += cnt
                    writer.write_rows(data_rows)

            while pending:
                _drain_one()

            total_rows_processed += sheet_total_rows
            sheet_reports.append(
                {
                    "sheet_name": sname,
                    "total_rows": sheet_total_rows,
                    "data_rows": sheet_data_rows,
                    "passthrough_only": passthrough_only,
                    "masked_columns": [
                        {
                            "col_index": active[i][0],
                            "col_name": active[i][1],
                            "rule": active[i][2]["rule"],
                            "masked_count": col_counts[i],
                        }
                        for i in range(len(active))
                    ],
                }
            )

        close_iter = getattr(sheet_iter, "close", None)
        if callable(close_iter):
            close_iter()
        writer.close()
        os.replace(tmp_output, target_output)
    except Exception:
        writer.close()
        if os.path.exists(tmp_output):
            try:
                os.remove(tmp_output)
            except OSError:
                pass
        raise
    finally:
        close_iter = getattr(sheet_iter, "close", None)
        if callable(close_iter):
            close_iter()
        if pool is not None:
            pool.shutdown(wait=True)

    elapsed_s = max(1e-6, time.perf_counter() - t0)
    elapsed_ms = int(elapsed_s * 1000)
    return {
        "status": "ok",
        "command": "apply",
        "input_file": str(Path(input_path)),
        "output_file": str(Path(target_output)),
        "input_format": file_fmt,
        "upgraded_from_xls": upgraded_from_xls,
        "read_engine": read_engine,
        "write_engine": writer.backend,
        "workers": eff_workers,
        "chunk_size": chunk_size,
        "used_salt": used_salt,
        "salt_mode": salt_mode,
        "elapsed_ms": elapsed_ms,
        "rows_per_sec": int(total_rows_processed / elapsed_s),
        "total_rows_processed": total_rows_processed,
        "total_cells_masked": total_cells_masked,
        "sheets": sheet_reports,
    }
