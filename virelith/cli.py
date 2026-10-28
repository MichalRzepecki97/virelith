"""MVP: local on-demand scan, no quarantine, no file execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from datetime import datetime, timezone

from .pe_analyzer import analyze_pe
from .heuristic_engine import evaluate_heuristics
from .active_rules import load_active_rules
from .scan_history import save_scan
from .insight import explain_pe_signals, explain_imports


def scan_clamav(path: Path, exe: str) -> dict:
    try:
        completed = subprocess.run([exe, "--no-summary", str(path)], capture_output=True,
                                   text=True, timeout=180, errors="replace")
        status = {0: "no_detection", 1: "detected", 2: "error"}.get(completed.returncode, "error")
        return {"status": status, "detail": (completed.stdout + completed.stderr).strip()[-4000:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "detail": str(exc)}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def scan_yara(path: Path, compiled_rules, max_size: int) -> dict:
    try:
        if path.stat().st_size > max_size:
            return {"status": "skipped", "detail": "size limit"}
        data = path.read_bytes()
        result = compiled_rules.scan(data)
        hits = [rule.identifier for rule in result.matching_rules]
        return {"status": "detected" if hits else "no_detection", "matches": hits}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


def scan_one(path: Path, clam_exe: str, rules, max_yara_bytes: int) -> dict:
    item = {"path": str(path), "sha256": None, "clamav": None, "yara": None, "pe_analysis": None, "heuristics": None}
    try:
        item["sha256"] = sha256_file(path)
    except OSError as exc:
        item["error"] = str(exc)
        item["verdict"] = "error"
        return item
    item["pe_analysis"] = analyze_pe(path)
    item["heuristics"] = evaluate_heuristics(item["pe_analysis"])
    item["insight"] = explain_pe_signals(item["heuristics"]) + explain_imports(item["pe_analysis"])
    item["clamav"] = scan_clamav(path, clam_exe)
    item["yara"] = scan_yara(path, rules, max_yara_bytes)
    states = {item["clamav"]["status"], item["yara"]["status"]}
    # A matching local test rule is a detection, not a proven malicious classification.
    if "detected" in states:
        item["verdict"] = "detection"
    elif states == {"no_detection"}:
        item["verdict"] = "no_detection"
    else:
        item["verdict"] = "incomplete"
    return item


class ScanLimitExceeded(RuntimeError):
    """Traversal stopped deliberately; results are incomplete."""


def files_under(target: Path, *, max_files=500, max_depth=8, max_total_mb=256):
    """Yield regular files without following symlinks, with bounded traversal.

    Limits bound the analysis workload, not total directory enumeration time.
    Filesystem content can change between validation and scanning.
    """
    if target.is_symlink():
        raise ValueError("Symlink targets are not permitted")
    max_total_bytes = max_total_mb * 1024 * 1024
    count = 0
    total_bytes = 0

    def accept(path):
        nonlocal count, total_bytes
        if path.is_symlink() or not path.is_file():
            return False
        size = path.stat().st_size
        if count >= max_files:
            raise ScanLimitExceeded(f"maximum file count reached ({max_files})")
        if total_bytes + size > max_total_bytes:
            raise ScanLimitExceeded(f"maximum total input size reached ({max_total_mb} MiB)")
        count += 1
        total_bytes += size
        return True

    if target.is_file():
        if accept(target):
            yield target
    elif target.is_dir():
        root_depth = len(target.parts)
        for root, dirs, filenames in os.walk(target, followlinks=False):
            depth = len(Path(root).parts) - root_depth
            dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())
            if depth >= max_depth:
                if dirs:
                    raise ScanLimitExceeded(f"maximum directory depth reached ({max_depth})")
                dirs.clear()
            for name in sorted(filenames):
                path = Path(root) / name
                try:
                    if accept(path):
                        yield path
                except OSError as exc:
                    raise ScanLimitExceeded(f"cannot inspect {path}: {exc}") from exc
    else:
        raise FileNotFoundError(str(target))


def save_report_atomic(path: Path, payload: dict) -> None:
    """Replace the checkpoint atomically in the report directory."""
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".virelith-", suffix=".json",
                                         delete=False) as stream:
            tmp = Path(stream.name)
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def heartbeat_until(stop: threading.Event, interval: float = 20.0) -> None:
    """Liveness signal, NOT evidence a scan made progress."""
    while not stop.wait(interval):
        print("VIRELITH_HEARTBEAT " + json.dumps({"monotonic": time.monotonic()}), flush=True)


def report_payload(args, results, metadata, *, complete=False, error=None):
    return {"schema": 1, "created_utc": args.created_utc,
            "target": str(args.target), "yara_rules": metadata,
            "files": list(results), "traversal_error": error, "complete": complete}


def main():
    parser = argparse.ArgumentParser(description="Virelith MVP local scanner")
    parser.add_argument("target", type=Path, help="file or directory")
    parser.add_argument("--clam", default="clamscan.exe" if os.name == "nt" else "clamscan")
    parser.add_argument("--rules", type=Path, default=Path(__file__).resolve().parent.parent / "rules" / "test_rule.yar")
    parser.add_argument("--rule-store", type=Path, help="use activated signed rules in this trusted store")
    parser.add_argument("--report", type=Path, default=Path("scan-report.json"))
    parser.add_argument("--history-db", type=Path, help="optional local SQLite scan history")
    parser.add_argument("--max-yara-mb", type=int, default=64)
    parser.add_argument("--max-files", type=int, default=500, help="maximum files per scan (default: 500)")
    parser.add_argument("--max-depth", type=int, default=8, help="maximum directory depth (default: 8)")
    parser.add_argument("--max-total-mb", type=int, default=256, help="maximum cumulative file size in MiB (default: 256)")
    args = parser.parse_args()
    if args.max_files < 1 or args.max_depth < 0 or args.max_total_mb < 1:
        parser.error("--max-files and --max-total-mb must be positive; --max-depth must be nonnegative")
    if args.max_yara_mb < 1:
        parser.error("--max-yara-mb must be >= 1")
    if args.rule_store is not None and args.rules != parser.get_default("rules"):
        parser.error("--rules and --rule-store cannot be combined")
    import yara_x
    try:
        if args.rule_store is not None:
            rule_source, rule_metadata = load_active_rules(args.rule_store)
        else:
            rule_source = args.rules.read_text(encoding="utf-8")
            rule_metadata = {"source": "local_file", "path": str(args.rules)}
        compiled = yara_x.compile(rule_source)
    except Exception as exc:
        parser.error(f"Cannot compile rules: {exc}")
    results = []
    traversal_error = None
    args.created_utc = datetime.now(timezone.utc).isoformat()
    save_report_atomic(args.report, report_payload(args, results, rule_metadata))
    heartbeat_stop = threading.Event()
    heartbeat_thread = threading.Thread(target=heartbeat_until, args=(heartbeat_stop,), daemon=True)
    heartbeat_thread.start()
    try:
        for path in files_under(args.target, max_files=args.max_files,
                                max_depth=args.max_depth, max_total_mb=args.max_total_mb):
            result = scan_one(path, args.clam, compiled, args.max_yara_mb * 1024 * 1024)
            results.append(result)
            save_report_atomic(args.report, report_payload(args, results, rule_metadata))
            print(f"{result['verdict']:>12} {path}", flush=True)
            print("VIRELITH_PROGRESS " + json.dumps({"processed": len(results), "detections": sum(r["verdict"] == "detection" for r in results)}), flush=True)
    except FileNotFoundError:
        traversal_error = f"Target not found: {args.target}"
    except (ScanLimitExceeded, ValueError, OSError) as exc:
        traversal_error = str(exc)
        print(f"Scan incomplete: {exc}", file=__import__("sys").stderr)
    heartbeat_stop.set()
    heartbeat_thread.join(timeout=1)
    payload = report_payload(args, results, rule_metadata, complete=traversal_error is None, error=traversal_error)
    save_report_atomic(args.report, payload)
    print(f"Report: {args.report.resolve()}")
    if args.history_db is not None:
        try:
            scan_id = save_scan(args.history_db, payload)
            print(f"History ID: {scan_id}")
        except (OSError, ValueError, __import__("sqlite3").Error) as exc:
            print(f"History save failed: {exc}", file=__import__("sys").stderr)
            return 2
    if traversal_error:
        return 2
    if any(r["verdict"] == "detection" for r in results):
        return 1
    if not results or any(r["verdict"] != "no_detection" for r in results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
