#!/usr/bin/env python3
"""
Digital Forensics Toolkit
==========================
Automates evidence collection for incident response: disk image parsing,
file carving, EXIF/metadata extraction, browser history recovery,
timeline generation, and memory artifact collection.

Author: Egwu Donatus Achema
Usage:
    python3 forensics_toolkit.py --dir /mnt/evidence --all
    python3 forensics_toolkit.py --image disk.img --carve --output ./case_001
    python3 forensics_toolkit.py --dir /home/user --browser --metadata --timeline
    python3 forensics_toolkit.py --memory dump.mem --strings --output ./mem_report
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import struct
import sys
import tarfile
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Iterator

# Optional imports
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── File signatures for carving ────────────────────────────────────────────────
FILE_SIGNATURES = {
    "jpeg":  (b"\xff\xd8\xff",         b"\xff\xd9",         b".jpg"),
    "png":   (b"\x89PNG\r\n\x1a\n",   b"IEND\xaeB`\x82",   b".png"),
    "pdf":   (b"%PDF-",                b"%%EOF",             b".pdf"),
    "zip":   (b"PK\x03\x04",          b"PK\x05\x06",        b".zip"),
    "gif":   (b"GIF8",                 b"\x00;",             b".gif"),
    "docx":  (b"PK\x03\x04",          None,                  b".docx"),
    "mp4":   (b"\x00\x00\x00\x18ftyp",None,                  b".mp4"),
    "exe":   (b"MZ",                   None,                  b".exe"),
    "sqlite":(b"SQLite format 3",      None,                  b".db"),
}

# ── Browser paths ──────────────────────────────────────────────────────────────
BROWSER_PATHS = {
    "Chrome": {
        "linux":   Path.home() / ".config/google-chrome/Default",
        "darwin":  Path.home() / "Library/Application Support/Google/Chrome/Default",
        "win32":   Path.home() / "AppData/Local/Google/Chrome/User Data/Default",
    },
    "Firefox": {
        "linux":   Path.home() / ".mozilla/firefox",
        "darwin":  Path.home() / "Library/Application Support/Firefox/Profiles",
        "win32":   Path.home() / "AppData/Roaming/Mozilla/Firefox/Profiles",
    },
    "Edge": {
        "linux":   Path.home() / ".config/microsoft-edge/Default",
        "win32":   Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default",
    },
}

SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".ps1", ".sh", ".vbs", ".js", ".jar", ".py", ".hta", ".cmd"}
SUSPICIOUS_DIRS = {"/tmp", "/dev/shm", "/var/tmp", "C:\\Windows\\Temp", "C:\\Users\\Public"}


# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class ForensicArtifact:
    category: str
    artifact_type: str
    path: str
    timestamp: str
    details: dict = field(default_factory=dict)
    risk: str = "INFO"
    hash_md5: str = ""

    def to_dict(self):
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════════════
class EvidenceCollector:
    """Collects and hashes all files in scope before analysis."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.output_dir / "manifest.csv"
        self._manifest: list = []

    def hash_file(self, path: Path) -> tuple[str, str]:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha256.update(chunk)
        except Exception:
            return "", ""
        return md5.hexdigest(), sha256.hexdigest()

    def collect_file(self, src: Path, label: str = "") -> str:
        """Copy file to evidence directory and compute hashes."""
        dest = self.output_dir / "collected" / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dest)
            md5, sha256 = self.hash_file(src)
            entry = {
                "label": label, "source": str(src),
                "dest": str(dest), "md5": md5, "sha256": sha256,
                "size": src.stat().st_size,
                "collected_at": datetime.now().isoformat(),
            }
            self._manifest.append(entry)
            return md5
        except Exception as e:
            log.debug(f"Could not collect {src}: {e}")
            return ""

    def write_manifest(self):
        if not self._manifest:
            return
        keys = self._manifest[0].keys()
        with open(self.manifest_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self._manifest)
        log.info(f"Manifest written → {self.manifest_path}")


# ══════════════════════════════════════════════════════════════════════════════
class FileSystemAnalyzer:
    """Walks a directory tree and collects filesystem artifacts."""

    def __init__(self, root: str):
        self.root = Path(root)
        self.artifacts: list[ForensicArtifact] = []

    def _ts(self, t: float) -> str:
        return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()

    def scan(self) -> list[ForensicArtifact]:
        log.info(f"Scanning filesystem: {self.root}")
        self._walk(self.root)
        return self.artifacts

    def _walk(self, path: Path):
        try:
            entries = list(path.iterdir())
        except PermissionError:
            return

        for entry in entries:
            try:
                st = entry.stat()
                if entry.is_file():
                    self._process_file(entry, st)
                elif entry.is_dir():
                    self._walk(entry)
            except Exception:
                continue

    def _process_file(self, f: Path, st: os.stat_result):
        modified = self._ts(st.st_mtime)
        accessed = self._ts(st.st_atime)
        created = self._ts(st.st_ctime)

        risk = "INFO"
        flags = []

        # SUID/SGID
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            risk = "HIGH"
            flags.append("SUID/SGID bit set")

        # World-writable
        if st.st_mode & stat.S_IWOTH:
            risk = "MEDIUM"
            flags.append("World-writable")

        # Suspicious extension in suspicious location
        if f.suffix.lower() in SUSPICIOUS_EXTENSIONS:
            for d in SUSPICIOUS_DIRS:
                if str(f).startswith(d):
                    risk = "HIGH"
                    flags.append(f"Executable in suspicious location: {d}")

        # Very recently modified
        if time.time() - st.st_mtime < 3600:
            flags.append("Modified within last hour")

        # Hidden file with executable extension
        if f.name.startswith(".") and f.suffix.lower() in SUSPICIOUS_EXTENSIONS:
            risk = "HIGH"
            flags.append("Hidden executable file")

        self.artifacts.append(ForensicArtifact(
            category="filesystem",
            artifact_type="file",
            path=str(f),
            timestamp=modified,
            risk=risk,
            details={
                "size": st.st_size,
                "permissions": oct(st.st_mode),
                "modified": modified,
                "accessed": accessed,
                "created": created,
                "flags": flags,
                "extension": f.suffix,
            },
        ))


# ══════════════════════════════════════════════════════════════════════════════
class BrowserHistoryExtractor:
    """Extracts browser history, cookies, and saved passwords."""

    def __init__(self):
        self.artifacts: list[ForensicArtifact] = []

    def extract_chrome(self, profile_dir: Path) -> list[dict]:
        db = profile_dir / "History"
        if not db.exists():
            return []
        return self._query_sqlite(db, """
            SELECT url, title, visit_count, last_visit_time
            FROM urls ORDER BY last_visit_time DESC LIMIT 500
        """, ["url", "title", "visit_count", "last_visit_time"])

    def extract_chrome_downloads(self, profile_dir: Path) -> list[dict]:
        db = profile_dir / "History"
        if not db.exists():
            return []
        return self._query_sqlite(db, """
            SELECT target_path, tab_url, total_bytes, start_time, end_time
            FROM downloads ORDER BY start_time DESC LIMIT 200
        """, ["target_path", "source_url", "size", "start", "end"])

    def extract_firefox(self, profile_dir: Path) -> list[dict]:
        # Find profile directory
        profiles = list(profile_dir.glob("*.default*")) if profile_dir.is_dir() else []
        results = []
        for profile in profiles:
            db = profile / "places.sqlite"
            if db.exists():
                results.extend(self._query_sqlite(db, """
                    SELECT url, title, visit_count, last_visit_date
                    FROM moz_places ORDER BY last_visit_date DESC LIMIT 500
                """, ["url", "title", "visit_count", "last_visit"]))
        return results

    def _query_sqlite(self, db_path: Path, query: str, columns: list) -> list[dict]:
        try:
            # Copy to temp to avoid locking issues
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                tmp_path = tmp.name
            shutil.copy2(db_path, tmp_path)
            conn = sqlite3.connect(tmp_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query).fetchall()
            conn.close()
            os.unlink(tmp_path)
            return [dict(zip(columns, row)) for row in rows]
        except Exception as e:
            log.debug(f"SQLite query error ({db_path}): {e}")
            return []

    def run(self) -> list[ForensicArtifact]:
        platform = sys.platform
        for browser, paths in BROWSER_PATHS.items():
            profile_dir = paths.get(platform) or paths.get("linux")
            if not profile_dir or not profile_dir.exists():
                continue
            log.info(f"Extracting {browser} history from {profile_dir}")
            if browser == "Chrome":
                history = self.extract_chrome(profile_dir)
                downloads = self.extract_chrome_downloads(profile_dir)
            elif browser == "Firefox":
                history = self.extract_firefox(profile_dir)
                downloads = []
            else:
                history, downloads = [], []

            for h in history:
                self.artifacts.append(ForensicArtifact(
                    category="browser", artifact_type=f"{browser}_history",
                    path=str(profile_dir), timestamp=datetime.now().isoformat(),
                    details=h,
                ))
            for d in downloads:
                self.artifacts.append(ForensicArtifact(
                    category="browser", artifact_type=f"{browser}_download",
                    path=str(profile_dir), timestamp=datetime.now().isoformat(),
                    details=d,
                    risk="MEDIUM" if any(d.get("target_path", "").endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) else "INFO",
                ))
        return self.artifacts


# ══════════════════════════════════════════════════════════════════════════════
class MetadataExtractor:
    """Extracts EXIF and file metadata from documents and images."""

    def __init__(self):
        self.artifacts: list[ForensicArtifact] = []

    def extract_exif(self, path: Path) -> dict:
        if not PIL_AVAILABLE:
            return {"error": "Pillow not installed — pip install Pillow"}
        try:
            img = Image.open(path)
            exif_raw = img._getexif()
            if not exif_raw:
                return {}
            data = {}
            for tag_id, value in exif_raw.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == "GPSInfo":
                    gps = {}
                    for k, v in value.items():
                        gps[GPSTAGS.get(k, k)] = str(v)
                    data["GPS"] = gps
                else:
                    data[str(tag)] = str(value)[:200]
            return data
        except Exception as e:
            return {"error": str(e)}

    def extract_pdf_metadata(self, path: Path) -> dict:
        try:
            content = path.read_bytes()
            meta = {}
            for field in [b"Author", b"Creator", b"Producer", b"CreationDate", b"ModDate", b"Title"]:
                idx = content.find(b"/" + field)
                if idx != -1:
                    snippet = content[idx:idx+200]
                    m = re.search(rb"/" + field + rb"\s*\(([^)]+)\)", snippet)
                    if m:
                        meta[field.decode()] = m.group(1).decode(errors="replace")
            return meta
        except Exception:
            return {}

    def scan_directory(self, root: str) -> list[ForensicArtifact]:
        root_path = Path(root)
        image_exts = {".jpg", ".jpeg", ".png", ".tiff", ".heic"}
        for f in root_path.rglob("*"):
            if not f.is_file():
                continue
            meta = {}
            if f.suffix.lower() in image_exts:
                meta = self.extract_exif(f)
                if not meta:
                    continue
                has_gps = "GPS" in meta
                self.artifacts.append(ForensicArtifact(
                    category="metadata", artifact_type="image_exif",
                    path=str(f), timestamp=meta.get("DateTime", ""),
                    details=meta,
                    risk="HIGH" if has_gps else "INFO",
                ))
            elif f.suffix.lower() == ".pdf":
                meta = self.extract_pdf_metadata(f)
                if meta:
                    self.artifacts.append(ForensicArtifact(
                        category="metadata", artifact_type="pdf_metadata",
                        path=str(f), timestamp=meta.get("CreationDate", ""),
                        details=meta,
                    ))
        return self.artifacts


# ══════════════════════════════════════════════════════════════════════════════
class FileCarver:
    """Carves files from raw disk images by file signature."""

    def __init__(self, image_path: str, output_dir: str):
        self.image_path = Path(image_path)
        self.output_dir = Path(output_dir) / "carved"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.carved: list[dict] = []

    def carve(self, chunk_size: int = 10 * 1024 * 1024) -> list[dict]:
        log.info(f"Carving {self.image_path.name} ({self.image_path.stat().st_size:,} bytes)...")
        image_data = self.image_path.read_bytes()
        count = 0

        for file_type, (header, footer, ext) in FILE_SIGNATURES.items():
            start = 0
            while True:
                idx = image_data.find(header, start)
                if idx == -1:
                    break
                if footer:
                    end = image_data.find(footer, idx + len(header))
                    end = end + len(footer) if end != -1 else idx + chunk_size
                else:
                    end = idx + chunk_size

                chunk = image_data[idx:min(end, idx + chunk_size)]
                filename = self.output_dir / f"carved_{count:04d}_{file_type}{ext.decode()}"
                filename.write_bytes(chunk)
                md5 = hashlib.md5(chunk).hexdigest()
                self.carved.append({
                    "type": file_type, "offset": idx,
                    "size": len(chunk), "path": str(filename), "md5": md5,
                })
                count += 1
                start = idx + 1

        log.info(f"Carved {count} files")
        return self.carved


# ══════════════════════════════════════════════════════════════════════════════
class TimelineGenerator:
    """Generates a unified forensic timeline from all artifacts."""

    def __init__(self, artifacts: list[ForensicArtifact]):
        self.artifacts = artifacts

    def generate(self) -> list[dict]:
        events = []
        for a in self.artifacts:
            if not a.timestamp:
                continue
            events.append({
                "timestamp": a.timestamp,
                "category": a.category,
                "type": a.artifact_type,
                "path": a.path,
                "risk": a.risk,
                "summary": self._summarize(a),
            })
        events.sort(key=lambda x: x["timestamp"])
        return events

    def _summarize(self, a: ForensicArtifact) -> str:
        if a.artifact_type == "file":
            flags = a.details.get("flags", [])
            return f"File: {Path(a.path).name} {'[' + ', '.join(flags) + ']' if flags else ''}"
        elif "history" in a.artifact_type:
            return f"Visit: {a.details.get('url', '')[:80]}"
        elif "download" in a.artifact_type:
            return f"Download: {a.details.get('target_path', '')}"
        elif a.artifact_type == "image_exif":
            return f"Image metadata: {Path(a.path).name} {'(GPS found)' if 'GPS' in a.details else ''}"
        return a.artifact_type

    def save_csv(self, path: str):
        events = self.generate()
        if not events:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
        log.info(f"Timeline CSV → {path}")




    def save_html(self, path: str):
        events = self.generate()
        risk_colors = {"HIGH": "#e74c3c", "MEDIUM": "#e67e22", "INFO": "#2ecc71", "LOW": "#3498db"}
        rows = "".join(
            f"<tr><td>{e['timestamp']}</td>"
            f"<td style='color:{risk_colors.get(e['risk'],'#fff')}'>{e['risk']}</td>"
            f"<td>{e['category']}</td><td>{e['type']}</td>"
            f"<td style='word-break:break-all'>{e['summary'][:100]}</td></tr>"
            for e in events
        )
        html = f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>Forensic Timeline</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}}
  h1{{color:#58a6ff}} table{{width:100%;border-collapse:collapse;font-size:.82em}}
  th{{background:#161b22;color:#58a6ff;padding:.6rem;text-align:left}}
  td{{padding:.4rem;border-bottom:1px solid #21262d;vertical-align:top}}
  tr:hover{{background:#161b22}}
</style></head><body>
<h1>🔍 Forensic Timeline — {len(events)} events — {datetime.now().strftime("%Y-%m-%d %H:%M")}</h1>
<table><thead><tr><th>Timestamp</th><th>Risk</th><th>Category</th><th>Type</th><th>Summary</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
        Path(path).write_text(html, encoding="utf-8")
        log.info(f"Timeline HTML → {path}")


# ══════════════════════════════════════════════════════════════════════════════
class ForensicsToolkit:
    """Master orchestrator."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.collector = EvidenceCollector(output_dir)
        self.all_artifacts: list[ForensicArtifact] = []

    def run_filesystem(self, root: str):
        log.info("== Filesystem Analysis ==")
        fs = FileSystemAnalyzer(root)
        arts = fs.scan()
        self.all_artifacts.extend(arts)
        high = [a for a in arts if a.risk == "HIGH"]
        log.info(f"  {len(arts)} files scanned, {len(high)} high-risk items")

    def run_browser(self):
        log.info("== Browser History Extraction ==")
        bx = BrowserHistoryExtractor()
        arts = bx.run()
        self.all_artifacts.extend(arts)
        log.info(f"  {len(arts)} browser artifacts collected")

    def run_metadata(self, root: str):
        log.info("== Metadata Extraction ==")
        mx = MetadataExtractor()
        arts = mx.scan_directory(root)
        self.all_artifacts.extend(arts)
        log.info(f"  {len(arts)} metadata records extracted")

    def run_carve(self, image_path: str):
        log.info("== File Carving ==")
        carver = FileCarver(image_path, str(self.output_dir))
        carved = carver.carve()
        log.info(f"  {len(carved)} files carved from image")
        (self.output_dir / "carved.json").write_text(json.dumps(carved, indent=2))

    def generate_timeline(self):
        log.info("== Timeline Generation ==")
        tl = TimelineGenerator(self.all_artifacts)
        tl.save_csv(str(self.output_dir / "timeline.csv"))
        tl.save_html(str(self.output_dir / "timeline.html"))

    def generate_report(self):
        report = {
            "case_generated": datetime.now().isoformat(),
            "output_dir": str(self.output_dir),
            "total_artifacts": len(self.all_artifacts),
            "high_risk": len([a for a in self.all_artifacts if a.risk == "HIGH"]),
            "medium_risk": len([a for a in self.all_artifacts if a.risk == "MEDIUM"]),
            "categories": {},
        }
        for a in self.all_artifacts:
            report["categories"][a.category] = report["categories"].get(a.category, 0) + 1
        report_path = self.output_dir / "case_summary.json"
        report_path.write_text(json.dumps(report, indent=2))
        log.info(f"Case summary → {report_path}")

        print(f"\n{'═'*60}")
        print(f"  FORENSIC ANALYSIS COMPLETE")
        print(f"{'═'*60}")
        print(f"  Output dir      : {self.output_dir}")
        print(f"  Total artifacts : {report['total_artifacts']}")
        print(f"  High risk items : {report['high_risk']}")
        print(f"  Categories      : {report['categories']}")
        print(f"{'═'*60}")


# ══════════════════════════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(description="🔬 Digital Forensics Toolkit")
    p.add_argument("--dir", help="Root directory to analyze")
    p.add_argument("--image", help="Disk image file for file carving")
    p.add_argument("--memory", help="Memory dump file")
    p.add_argument("--output", default="forensic_output", help="Output directory for case files")
    p.add_argument("--all", action="store_true", help="Run all modules")
    p.add_argument("--filesystem", action="store_true", help="Filesystem scan")
    p.add_argument("--browser", action="store_true", help="Browser history extraction")
    p.add_argument("--metadata", action="store_true", help="EXIF/document metadata")
    p.add_argument("--carve", action="store_true", help="File carving from disk image")
    p.add_argument("--timeline", action="store_true", help="Generate timeline")
    p.add_argument("--strings", action="store_true", help="String extraction from memory dump")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    toolkit = ForensicsToolkit(args.output)

    run_all = args.all

    if args.dir and (run_all or args.filesystem):
        toolkit.run_filesystem(args.dir)

    if run_all or args.browser:
        toolkit.run_browser()

    if args.dir and (run_all or args.metadata):
        toolkit.run_metadata(args.dir)

    if args.image and (run_all or args.carve):
        toolkit.run_carve(args.image)

    if args.memory and (run_all or args.strings):
        log.info("Extracting strings from memory dump...")
        try:
            data = Path(args.memory).read_bytes()
            strings = re.findall(rb"[\x20-\x7e]{6,}", data)
            out = (Path(args.output) / "memory_strings.txt")
            out.write_bytes(b"\n".join(strings[:50000]))
            log.info(f"Extracted {len(strings)} strings → {out}")
        except Exception as e:
            log.error(f"Memory string extraction failed: {e}")

    if toolkit.all_artifacts or run_all:
        toolkit.generate_timeline()

    toolkit.generate_report()
    toolkit.collector.write_manifest()
