#!/usr/bin/env python3
"""
Download all 27 repositories and merge readable source files into a single
AiO Markdown file (with optional per-repo Markdown outputs).
Requires: Python 3.9+ and git. Zero third-party dependencies.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys

REPOS: list[str] = [
    "https://github.com/morluto/awesome-reverse-engineering",
    "https://github.com/reacher-z/Awesome-REA",
    "https://github.com/p-e-w/heretic",
    "https://github.com/PurpleDoubleD/locally-uncensored",
    "https://github.com/horsicq/Detect-It-Easy",
    "https://github.com/hasherezade/pe-bear",
    "https://github.com/erocarrera/pefile",
    "https://github.com/lief-project/LIEF",
    "https://github.com/capstone-engine/capstone",
    "https://github.com/NationalSecurityAgency/ghidra",
    "https://github.com/radareorg/radare2",
    "https://github.com/rizinorg/rizin",
    "https://github.com/rizinorg/cutter",
    "https://github.com/keystone-engine/keystone",
    "https://github.com/unicorn-engine/unicorn",
    "https://github.com/angr/angr",
    "https://github.com/x64dbg/x64dbg",
    "https://github.com/hasherezade/pe-sieve",
    "https://github.com/hasherezade/hollows_hunter",
    "https://github.com/mandiant/capa",
    "https://github.com/mandiant/flare-floss",
    "https://github.com/microsoft/Detours",
    "https://github.com/frida/frida",
    "https://github.com/ThirteenAG/Ultimate-ASI-Loader",
    "https://github.com/wietze/HijackLibs",
    "https://github.com/winsiderss/systeminformer",
    "https://github.com/nefarius/ViGEmBus",
]

SKIP_DIRS = {
    ".git",
    ".github",
    "node_modules",
    "target",
    "build",
    "dist",
    "out",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".idea",
    ".vs",
    "Pods",
}

BINARY_EXTS = {
    ".exe", ".dll", ".so", ".dylib", ".sys", ".lib", ".a", ".o", ".obj",
    ".pdb", ".bin", ".dat", ".elf", ".class", ".jar", ".war", ".pyc", ".pyo",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".icns", ".webp", ".tiff",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".avi", ".mov", ".webm",
    ".sqlite", ".db", ".pch", ".ilk", ".exp", ".res", ".wasm",
}

NOISE_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "composer.lock",
}

NOISE_SUFFIXES = (".min.js", ".min.css", ".map")

LANG_MAP = {
    ".py": "python",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "csharp",
    ".java": "java",
    ".kt": "kotlin",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "jsx",
    ".go": "go",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "zsh",
    ".ps1": "powershell",
    ".bat": "bat",
    ".cmd": "bat",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
    ".sql": "sql",
    ".md": "markdown",
    ".cmake": "cmake",
    ".asm": "nasm",
    ".s": "asm",
    ".S": "asm",
    ".meson": "meson",
}


def repo_name(url: str) -> str:
    return url.rstrip("/").split("/")[-1]


def clone_or_update(url: str, clone_dir: Path, update: bool, submodules: bool) -> tuple[str, bool, str]:
    name = repo_name(url)
    dest = clone_dir / name

    if dest.exists():
        if not update:
            return name, True, "already cloned"
        cmd = ["git", "-C", str(dest), "pull", "--ff-only"]
    else:
        cmd = ["git", "clone", "--depth", "1", "--single-branch"]
        if submodules:
            cmd.append("--recurse-submodules")
        cmd.extend([url, str(dest)])

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["unknown git error"]
        return name, False, err[0]
    return name, True, "ok"


def git_head_sha(repo_dir: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def is_readable_text(path: Path) -> tuple[bool, str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return False, "unreadable"

    if not raw:
        return True, ""

    # Null byte check catches binaries cleanly
    if b"\x00" in raw[:16384]:
        return False, "binary"

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return False, "non-text"

    # Reject files dominated by non-printable control characters
    sample = text[:8192]
    ctrl = sum(1 for ch in sample if ord(ch) < 32 and ch not in "\n\r\t")
    if sample and (ctrl / len(sample)) > 0.05:
        return False, "control-chars"

    return True, text.replace("\r\n", "\n").replace("\r", "\n")


def safe_fence(text: str) -> str:
    runs = [len(m.group(0)) for m in re.finditer(r"`+", text)]
    return "`" * max(3, (max(runs) + 1) if runs else 3)


def detect_lang(path: Path) -> str:
    if path.name == "CMakeLists.txt":
        return "cmake"
    if path.name in {"Makefile", "GNUmakefile"}:
        return "makefile"
    if path.name == "Dockerfile":
        return "dockerfile"
    if path.name == "meson.build":
        return "meson"
    return LANG_MAP.get(path.suffix, path.suffix.lstrip(".").lower())


def should_skip(
    path: Path,
    repo_dir: Path,
    max_bytes: int,
    include_noise: bool,
) -> tuple[bool, str]:
    rel_parts = path.relative_to(repo_dir).parts
    if any(p in SKIP_DIRS for p in rel_parts[:-1]):
        return True, "skip-dir"

    if path.suffix.lower() in BINARY_EXTS:
        return True, "binary-ext"

    if not include_noise:
        if path.name in NOISE_FILENAMES or path.name.lower().endswith(NOISE_SUFFIXES):
            return True, "noise"
        if path.suffix.lower() == ".svg":
            return True, "svg"

    try:
        size = path.stat().st_size
    except OSError:
        return True, "stat-error"

    if max_bytes > 0 and size > max_bytes:
        return True, "too-large"

    return False, ""


def write_repo_markdown(
    url: str,
    repo_dir: Path,
    max_bytes: int,
    include_noise: bool,
) -> tuple[str, dict[str, int]]:
    name = repo_name(url)
    sha = git_head_sha(repo_dir)
    stats = {"files": 0, "lines": 0, "bytes": 0, "skipped_large": 0, "skipped_binary": 0}

    chunks: list[str] = [
        f"## Repo: {name}\n\n",
        f"- **URL**: {url}\n",
        f"- **Commit**: `{sha}`\n\n",
    ]

    for path in sorted(repo_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue

        skip, reason = should_skip(path, repo_dir, max_bytes, include_noise)
        if skip:
            if reason == "too-large":
                stats["skipped_large"] += 1
            elif reason in {"binary-ext"}:
                stats["skipped_binary"] += 1
            continue

        ok, content = is_readable_text(path)
        if not ok:
            stats["skipped_binary"] += 1
            continue

        rel = path.relative_to(repo_dir).as_posix()
        lang = detect_lang(path)
        fence = safe_fence(content)

        block = f"### `{name}/{rel}`\n\n{fence}{lang}\n{content}"
        if content and not content.endswith("\n"):
            block += "\n"
        block += f"{fence}\n\n"

        chunks.append(block)
        stats["files"] += 1
        stats["lines"] += content.count("\n") + (1 if content and not content.endswith("\n") else 0)
        stats["bytes"] += len(content.encode("utf-8", errors="replace"))

    chunks.insert(
        3,
        f"- **Included files**: {stats['files']:,} "
        f"({stats['lines']:,} lines, {stats['bytes'] / (1024 * 1024):.2f} MiB)\n"
        f"- **Skipped**: {stats['skipped_binary']:,} binary/non-text, "
        f"{stats['skipped_large']:,} oversized\n\n",
    )
    return "".join(chunks), stats


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Clone all 27 repos and merge readable source into a single AiO Markdown file."
    )
    parser.add_argument("--clone-dir", type=Path, default=Path("./repos"), help="Clone directory")
    parser.add_argument("--out", type=Path, default=Path("./all_repos_aio.md"), help="Output AiO Markdown path")
    parser.add_argument("--workers", type=int, default=4, help="Parallel git clone workers")
    parser.add_argument("--update", action="store_true", help="Pull updates for already-cloned repos")
    parser.add_argument("--submodules", action="store_true", help="Also clone git submodules")
    parser.add_argument(
        "--max-file-kb",
        type=int,
        default=512,
        help="Skip single files larger than N KB (0 = unlimited, default 512)",
    )
    parser.add_argument(
        "--include-noise",
        action="store_true",
        help="Include lockfiles, .min.js, .map, and .svg files",
    )
    parser.add_argument(
        "--split-dir",
        type=Path,
        default=None,
        help="Optional directory to also write one <repo>.md file per repo",
    )
    args = parser.parse_args()

    args.clone_dir.mkdir(parents=True, exist_ok=True)
    if args.split_dir:
        args.split_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1/2] Downloading {len(REPOS)} repositories into {args.clone_dir} (workers={args.workers})...")
    failures: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {
            pool.submit(clone_or_update, url, args.clone_dir, args.update, args.submodules): url
            for url in REPOS
        }
        for fut in as_completed(futures):
            name, ok, msg = fut.result()
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] {name}: {msg}")
            if not ok:
                failures.append((name, msg))

    max_bytes = args.max_file_kb * 1024 if args.max_file_kb > 0 else 0
    print(f"[2/2] Merging readable source code into {args.out} (max_file_kb={args.max_file_kb})...")

    repo_sections: list[tuple[str, str, dict[str, int]]] = []
    totals = {"files": 0, "lines": 0, "bytes": 0}

    for url in REPOS:
        name = repo_name(url)
        repo_dir = args.clone_dir / name
        if not repo_dir.exists():
            continue
        md_text, stats = write_repo_markdown(url, repo_dir, max_bytes, args.include_noise)
        repo_sections.append((name, md_text, stats))
        totals["files"] += stats["files"]
        totals["lines"] += stats["lines"]
        totals["bytes"] += stats["bytes"]

        if args.split_dir:
            (args.split_dir / f"{name}.md").write_text(md_text, encoding="utf-8")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    args.out.parent.mkdir(parents=True, exist_ok=True)

    with args.out.open("w", encoding="utf-8", errors="replace") as out:
        out.write("# All 27 Repositories — AiO Readable Source Code\n\n")
        out.write(f"- **Generated**: {now}\n")
        out.write(f"- **Repositories merged**: {len(repo_sections)} / {len(REPOS)}\n")
        out.write(
            f"- **Total readable source**: {totals['files']:,} files, "
            f"{totals['lines']:,} lines, {totals['bytes'] / (1024 * 1024):.2f} MiB\n\n"
        )

        if failures:
            out.write("### Clone Failures\n\n")
            for name, msg in failures:
                out.write(f"- `{name}`: {msg}\n")
            out.write("\n")

        out.write("## Table of Contents\n\n")
        for name, _, stats in repo_sections:
            anchor = f"repo-{name.lower()}"
            out.write(
                f"- [{name}](#{anchor}) — {stats['files']:,} files "
                f"({stats['bytes'] / (1024 * 1024):.2f} MiB)\n"
            )
        out.write("\n---\n\n")

        for _, md_text, _ in repo_sections:
            out.write(md_text)

    out_mb = args.out.stat().st_size / (1024 * 1024)
    print(f"Done: wrote {args.out} ({out_mb:.2f} MiB, {totals['files']:,} files).")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())