"""Build the public download bundle: website/cerberus-ai.zip.

Zips the source tree under a top-level cerberus-ai/ folder, deliberately leaving
out secrets and local state (.env, config.json, the SQLite DBs, outputs/) and dev
junk (.git, __pycache__, .venv). Re-run this any time the code changes:

    python build_release.py
"""

import os
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "website", "cerberus-ai.zip")

# Directories we never ship (local state, dev tooling, the website + build output).
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "outputs", "website", "node_modules", ".idea", ".vscode"}
# Exact filenames that hold secrets / machine-local state.
SKIP_FILES = {".env", "config.json", ".DS_Store", "build_release.py"}
# Suffixes to drop (compiled python, the SQLite DBs + their WAL/journal siblings).
SKIP_SUFFIXES = (".pyc", ".db", ".zip")


def _skip(rel: str) -> bool:
    name = os.path.basename(rel)
    if name in SKIP_FILES:
        return True
    if name.endswith(SKIP_SUFFIXES):
        return True
    if ".db-" in name or ".db." in name:   # cerberus_memory.db-wal, -shm, -journal
        return True
    return False


def main() -> None:
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    if os.path.exists(OUT):
        os.remove(OUT)
    count = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, ROOT).replace(os.sep, "/")
                if _skip(rel):
                    continue
                z.write(full, arcname=f"cerberus-ai/{rel}")
                count += 1
    size_kb = os.path.getsize(OUT) / 1024
    print(f"Wrote {OUT}")
    print(f"  {count} files, {size_kb:.0f} KB")


if __name__ == "__main__":
    main()
