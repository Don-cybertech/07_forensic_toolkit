"""
========================================
 Digital Forensics Toolkit
 Tools: os, sqlite3, Pillow, hashlib, re
 Run: python forensics.py --dir /path --output report/
========================================
"""

import os
import re
import sys
import json
import hashlib
import sqlite3
import argparse
import struct
import shutil
from datetime import datetime
from pathlib import Path

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_OK = True
except ImportError:
    print("[!] pip install Pillow  (EXIF/image analysis disabled)")
    PIL_OK = False


# ── Report State ───────────────────────────────────────────────
REPORT = {
    "case_id": None,
    "examiner": None,
    "source": None,
    "timestamp": datetime.now().isoformat(),
    "file_inventory": [],
    "exif_data": [],
    "browser_history": [],
    "email_artifacts": [],
    "deleted_files": [],
    "timeline": [],
    "hash_manifest": {},
    "summary": {},
}


# ── Utility ────────────────────────────────────────────────────
def log_timeline(event_type, path, timestamp, detail=""):
    REPORT["timeline"].append({
        "event": event_type, "path": str(path),
        "timestamp": timestamp, "detail": detail,
    })


def file_hash(path, algo="sha256"):
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ── 1. File System Inventory ───────────────────────────────────
INTERESTING_EXTENSIONS = {
    ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp4", ".avi",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".py", ".sh", ".bat", ".ps1", ".exe", ".dll",
    ".db", ".sqlite", ".sqlite3", ".mdb",
    ".log", ".txt", ".csv", ".json", ".xml",
    ".key", ".pem", ".crt", ".p12",
}

def inventory_files(root_dir):
    """Walk directory and catalog all files with metadata."""
    print(f"[*] Inventorying files in {root_dir}...")
    count = 0
    for root, dirs, files in os.walk(root_dir):
        # Skip system dirs
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", "node_modules"}]
        for fname in files:
            path = Path(root) / fname
            try:
                stat = path.stat()
                ext = path.suffix.lower()
                entry = {
                    "path": str(path),
                    "name": fname,
                    "extension": ext,
                    "size_bytes": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                    "interesting": ext in INTERESTING_EXTENSIONS,
                }
                REPORT["file_inventory"].append(entry)
                log_timeline("FILE_MODIFIED", path, entry["modified"])
                count += 1
            except (PermissionError, OSError):
                pass
    print(f"  Found {count} files")
    return count


# ── 2. Hash Manifest (Chain of Custody) ───────────────────────
def generate_hash_manifest(root_dir):
    """Generate SHA-256 hash for every file (chain of custody)."""
    print("[*] Generating hash manifest...")
    manifest = {}
    files = [e for e in REPORT["file_inventory"] if e["interesting"]]
    for entry in files:
        h = file_hash(entry["path"])
        if h:
            manifest[entry["path"]] = h
    REPORT["hash_manifest"] = manifest
    print(f"  Hashed {len(manifest)} interesting files")


# ── 3. EXIF Metadata Extraction ───────────────────────────────
def dms_to_decimal(dms, ref):
    """Convert GPS DMS to decimal degrees."""
    try:
        d, m, s = [float(x) for x in dms]
        decimal = d + m / 60 + s / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def extract_exif(root_dir):
    if not PIL_OK:
        return
    print("[*] Extracting EXIF metadata from images...")
    image_exts = {".jpg", ".jpeg", ".tiff", ".tif"}

    for entry in REPORT["file_inventory"]:
        if entry["extension"] not in image_exts:
            continue
        try:
            img = Image.open(entry["path"])
            exif_raw = img._getexif()
            if not exif_raw:
                continue

            exif = {TAGS.get(k, k): v for k, v in exif_raw.items()}
            record = {"file": entry["path"], "tags": {}}

            # Key fields
            for tag in ["Make", "Model", "Software", "DateTime", "Artist",
                        "Copyright", "ImageDescription", "UserComment"]:
                if tag in exif:
                    record["tags"][tag] = str(exif[tag])[:200]

            # GPS
            if "GPSInfo" in exif:
                gps = {GPSTAGS.get(k, k): v for k, v in exif["GPSInfo"].items()}
                lat = dms_to_decimal(gps.get("GPSLatitude", (0,0,0)), gps.get("GPSLatitudeRef", "N"))
                lon = dms_to_decimal(gps.get("GPSLongitude", (0,0,0)), gps.get("GPSLongitudeRef", "E"))
                if lat and lon:
                    record["tags"]["GPS_Latitude"] = lat
                    record["tags"]["GPS_Longitude"] = lon
                    record["tags"]["GPS_MapLink"] = f"https://maps.google.com/?q={lat},{lon}"
                    log_timeline("GPS_FOUND", entry["path"], entry["modified"],
                                 f"lat={lat}, lon={lon}")

            if record["tags"]:
                REPORT["exif_data"].append(record)
                print(f"  📷 {entry['name']}: {list(record['tags'].keys())}")

        except Exception:
            pass


# ── 4. Browser History Recovery ───────────────────────────────
BROWSER_DB_PATHS = {
    "Chrome": [
        "~/.config/google-chrome/Default/History",
        "~/Library/Application Support/Google/Chrome/Default/History",
        "C:/Users/{user}/AppData/Local/Google/Chrome/User Data/Default/History",
    ],
    "Firefox": [
        "~/.mozilla/firefox/*.default/places.sqlite",
    ],
}

def extract_browser_history(custom_db=None):
    """Extract browsing history from Chrome/Firefox SQLite DBs."""
    print("[*] Extracting browser history...")
    db_paths = []

    if custom_db:
        db_paths.append(("Custom", custom_db))
    else:
        for browser, paths in BROWSER_DB_PATHS.items():
            for p in paths:
                expanded = os.path.expanduser(p)
                if "*" in expanded:
                    import glob
                    db_paths += [(browser, x) for x in glob.glob(expanded)]
                elif os.path.exists(expanded):
                    db_paths.append((browser, expanded))

    for browser, db_path in db_paths:
        # Work on a copy (DB may be locked)
        tmp = f"/tmp/forensics_browser_{browser}.db"
        try:
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)
            cur = conn.cursor()

            if browser in ("Chrome", "Custom"):
                try:
                    cur.execute("""
                        SELECT url, title, visit_count, last_visit_time
                        FROM urls ORDER BY last_visit_time DESC LIMIT 500
                    """)
                    for row in cur.fetchall():
                        url, title, count, ts = row
                        # Chrome timestamp: microseconds since 1601-01-01
                        try:
                            epoch = (ts / 1_000_000) - 11644473600
                            visit_dt = datetime.fromtimestamp(epoch).isoformat()
                        except Exception:
                            visit_dt = str(ts)

                        REPORT["browser_history"].append({
                            "browser": browser, "url": url,
                            "title": title, "visits": count, "last_visit": visit_dt,
                        })
                except sqlite3.OperationalError:
                    pass

            elif browser == "Firefox":
                try:
                    cur.execute("""
                        SELECT url, title, visit_count, last_visit_date
                        FROM moz_places ORDER BY last_visit_date DESC LIMIT 500
                    """)
                    for row in cur.fetchall():
                        url, title, count, ts = row
                        try:
                            visit_dt = datetime.fromtimestamp(ts / 1_000_000).isoformat()
                        except Exception:
                            visit_dt = str(ts)
                        REPORT["browser_history"].append({
                            "browser": "Firefox", "url": url,
                            "title": title, "visits": count, "last_visit": visit_dt,
                        })
                except sqlite3.OperationalError:
                    pass

            conn.close()
            os.remove(tmp)
            print(f"  🌐 {browser}: {len([h for h in REPORT['browser_history'] if h['browser'] == browser])} URLs")

        except (shutil.Error, PermissionError, sqlite3.Error) as e:
            print(f"  [!] {browser} DB error: {e}")


# ── 5. Keyword / Pattern Search ────────────────────────────────
EMAIL_PATTERN  = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN  = re.compile(r"\b(\+?\d[\d\s\-().]{7,14}\d)\b")
CREDIT_PATTERN = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")
IP_PATTERN     = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

def keyword_search(root_dir, keywords=None):
    """Search text files for email addresses, PIIs, and custom keywords."""
    print(f"[*] Scanning for PII and keywords...")
    text_exts = {".txt", ".log", ".csv", ".json", ".xml", ".html", ".py", ".sh", ".bat", ".md"}
    findings = {"emails": set(), "phones": set(), "credit_cards": set(), "ips": set(), "keywords": {}}
    kw_list = keywords or []

    for entry in REPORT["file_inventory"]:
        if entry["extension"] not in text_exts or entry["size_bytes"] > 10 * 1024 * 1024:
            continue
        try:
            with open(entry["path"], "r", errors="ignore") as f:
                content = f.read()
            findings["emails"].update(EMAIL_PATTERN.findall(content))
            findings["phones"].update(PHONE_PATTERN.findall(content))
            findings["credit_cards"].update(CREDIT_PATTERN.findall(content))
            findings["ips"].update(IP_PATTERN.findall(content))
            for kw in kw_list:
                if kw.lower() in content.lower():
                    findings["keywords"].setdefault(kw, []).append(entry["path"])
        except Exception:
            pass

    REPORT["email_artifacts"] = list(findings["emails"])
    print(f"  📧 Emails found     : {len(findings['emails'])}")
    print(f"  📱 Phone numbers    : {len(findings['phones'])}")
    print(f"  💳 Credit card #s   : {len(findings['credit_cards'])}")
    print(f"  🌐 IP addresses     : {len(findings['ips'])}")


# ── 6. File Carving (Deleted Files) ───────────────────────────
FILE_SIGNATURES = {
    "JPEG": (b"\xff\xd8\xff", b"\xff\xd9"),
    "PNG":  (b"\x89PNG\r\n\x1a\n", b"IEND"),
    "PDF":  (b"%PDF-", b"%%EOF"),
    "ZIP":  (b"PK\x03\x04", b"PK\x05\x06"),
}

def carve_files(raw_image_path, output_dir):
    """Basic file carving from a raw disk image."""
    if not os.path.exists(raw_image_path):
        print(f"[!] Image not found: {raw_image_path}"); return

    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Carving files from {raw_image_path}...")
    carved = 0

    with open(raw_image_path, "rb") as f:
        data = f.read()

    for file_type, (header, footer) in FILE_SIGNATURES.items():
        offset = 0
        while True:
            start = data.find(header, offset)
            if start == -1:
                break
            end = data.find(footer, start + len(header))
            if end == -1:
                offset = start + 1
                continue
            end += len(footer)
            chunk = data[start:end]
            out_path = os.path.join(output_dir, f"carved_{carved:04d}.{file_type.lower()}")
            with open(out_path, "wb") as out:
                out.write(chunk)
            REPORT["deleted_files"].append({
                "type": file_type, "offset": start, "size": len(chunk), "output": out_path
            })
            carved += 1
            offset = end

    print(f"  Carved {carved} files → {output_dir}")


# ── Summary & Report ───────────────────────────────────────────
def generate_report(output_dir):
    os.makedirs(output_dir, exist_ok=True)

    # Sort timeline
    REPORT["timeline"].sort(key=lambda x: x["timestamp"])

    # Summary
    REPORT["summary"] = {
        "total_files": len(REPORT["file_inventory"]),
        "interesting_files": sum(1 for f in REPORT["file_inventory"] if f["interesting"]),
        "images_with_exif": len(REPORT["exif_data"]),
        "browser_history_urls": len(REPORT["browser_history"]),
        "emails_found": len(REPORT["email_artifacts"]),
        "carved_files": len(REPORT["deleted_files"]),
        "timeline_events": len(REPORT["timeline"]),
    }

    # JSON report
    json_path = os.path.join(output_dir, "forensics_report.json")
    with open(json_path, "w") as f:
        json.dump(REPORT, f, indent=2, default=str)

    # Timeline CSV
    csv_path = os.path.join(output_dir, "timeline.csv")
    with open(csv_path, "w") as f:
        f.write("timestamp,event,path,detail\n")
        for e in REPORT["timeline"]:
            f.write(f"{e['timestamp']},{e['event']},{e['path']},{e['detail']}\n")

    print(f"\n[+] Reports saved:")
    print(f"    JSON     → {json_path}")
    print(f"    Timeline → {csv_path}")


# ── Main ───────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="🔍 Digital Forensics Toolkit")
    parser.add_argument("--dir",        help="Directory to analyze")
    parser.add_argument("--image",      help="Raw disk image for file carving")
    parser.add_argument("--browser-db", help="Browser SQLite DB path (manual)")
    parser.add_argument("--keywords",   nargs="*", help="Custom keywords to search")
    parser.add_argument("--case-id",    default="CASE-001")
    parser.add_argument("--examiner",   default="Analyst")
    parser.add_argument("-o", "--output", default="forensics_output/")
    args = parser.parse_args()

    REPORT["case_id"]  = args.case_id
    REPORT["examiner"] = args.examiner
    REPORT["source"]   = args.dir or args.image

    print(f"\n{'='*55}")
    print(f"  🔍 Digital Forensics Toolkit")
    print(f"  Case ID  : {args.case_id}")
    print(f"  Examiner : {args.examiner}")
    print(f"  Source   : {REPORT['source']}")
    print(f"{'='*55}\n")

    if args.dir:
        inventory_files(args.dir)
        generate_hash_manifest(args.dir)
        extract_exif(args.dir)
        keyword_search(args.dir, args.keywords)

    extract_browser_history(args.browser_db)

    if args.image:
        carve_dir = os.path.join(args.output, "carved")
        carve_files(args.image, carve_dir)

    generate_report(args.output)

    print(f"\n{'='*55}")
    for k, v in REPORT["summary"].items():
        print(f"  {k:<30}: {v}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
