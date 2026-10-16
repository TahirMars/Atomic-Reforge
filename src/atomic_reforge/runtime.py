"""Build an embeddable (portable) Python runtime for offline `run`.

The evaluation machine typically has no Python and no network, so a `release`
bundle can optionally carry a self-contained CPython interpreter plus every
dependency the `run` command needs. This module assembles that runtime from an
official embeddable archive (``python-<ver>-embed-amd64.zip``) and copies the
already-installed project + third-party packages into it.

The runtime is intentionally **run-only**: it carries the full ``atomic_reforge``
package (kept whole to avoid re-architecting the CLI), but the intended offline
surface is just ``run`` (plus ``--check-integrity``). It does not provide
``generate``/``report`` capability as a product feature.
"""

from __future__ import annotations

import importlib
import io
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable, Optional

# The embeddable archive version and the C-extension ABI must match the
# interpreter that vendors the packages (the one running build_runtime), so
# derive both from the live interpreter rather than hardcoding. E.g.
# "3.13.3" -> tag "313"; the ._pth / .pyd tag is major+minor with the trailing
# zero stripped (python313._pth, .cp313-win_amd64.pyd).
RUNTIME_VER = ".".join(str(_v) for _v in sys.version_info[:3])
RUNTIME_TAG = "".join(RUNTIME_VER.split(".")[:2]).rstrip("0") or "0"
RUNTIME_URL = (
    f"https://www.python.org/ftp/python/{RUNTIME_VER}/"
    f"python-{RUNTIME_VER}-embed-amd64.zip"
)
_PTH_NAME = f"python{RUNTIME_TAG}._pth"
_EXT_MARKER = f".cp{RUNTIME_TAG}-win_amd64.pyd"

# Third-party pure-python packages to vendor (each resolved by import).
PURE_PACKAGES = [
    "pydantic",
    "annotated_types",
    "pydantic_core",  # dir carries the C ext too
    "annotated_doc",
    "typer",
    "rich",
    "markdown_it",
    "mdurl",
    "pygments",
    "shellingham",
    "typing_inspection",
    "click",
    "colorama",
    "ruamel",
    "yaml",
    "jsonschema",
    "jsonschema_specifications",
    "referencing",
    "attrs",
    "attr",
    "rpds",
    "typing_extensions",
]

# atomic_red_team is vendored from ref/ on the dev machine; it is NOT in the
# venv site-packages, so resolve it explicitly.
_REF_TEAM_DIR = Path(__file__).resolve().parents[2] / "ref" / "atomic-red-team-master"

_SKIP_DIR_SUFFIXES = (".dist-info", "__pycache__")


def _site_packages() -> Path:
    """The site-packages dir of the currently-running interpreter."""
    import site

    for p in site.getsitepackages():
        if "site-packages" in p:
            return Path(p)
    # fallback: stdlib Lib/site-packages
    return Path(sys.prefix) / "Lib" / "site-packages"


def _copy_tree(src: Path, dest: Path) -> int:
    n = 0
    for child in src.rglob("*"):
        rel = child.relative_to(src)
        # skip dist-info metadata, caches, and any non-matching C extensions
        if child.name == "__pycache__":
            continue
        if child.name.endswith(".dist-info"):
            continue
        if child.suffix == ".pyd" and _EXT_MARKER not in child.name:
            continue
        dst = dest / rel
        if child.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(child, dst)
        n += 1
    return n


def _resolve_package(name: str) -> Path | None:
    """Return the on-disk dir/module path for a top-level import, or None."""
    try:
        mod = importlib.import_module(name)
    except Exception:
        return None
    path = getattr(mod, "__path__", None)
    if path:  # package
        return Path(str(path[0]))
    f = getattr(mod, "__file__", None)
    if f:
        return Path(f)
    return None


def _copy_extension(name: str, site: Path, dest_sp: Path) -> int:
    """Copy a C-extension module (single .pyd or a subdir holding one)."""
    src = site / name
    if src.is_dir():
        return _copy_tree(src, dest_sp / name)
    candidates = sorted(site.glob(f"{name}{_EXT_MARKER}"))
    n = 0
    for c in candidates:
        dst = dest_sp / c.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(c, dst)
        n += 1
    return n


def _local_embed_zip() -> Path | None:
    """Prefer a pre-downloaded embed zip under ``ref/`` when present."""
    repo_ref = Path(__file__).resolve().parents[2] / "ref"
    candidates = [
        repo_ref / f"python-{RUNTIME_VER}-embed-amd64.zip",
        repo_ref / "python-3.13.3-embed-amd64.zip",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def download_embed(dest_dir: Path) -> Path:
    """Obtain and extract the embeddable CPython archive into dest_dir.

    Prefers ``ref/python-<ver>-embed-amd64.zip`` (offline-friendly) before
    downloading from python.org. Returns the directory containing
    ``python.exe``. Reuses an existing extract when present.
    """
    embed_root = dest_dir / f"python{RUNTIME_TAG}-embed-amd64"
    if (embed_root / "python.exe").is_file():
        return embed_root
    dest_dir.mkdir(parents=True, exist_ok=True)
    local_zip = _local_embed_zip()
    if local_zip is not None:
        print(f"[runtime] using local embed zip: {local_zip}")
        with zipfile.ZipFile(local_zip) as z:
            embed_root.mkdir(parents=True, exist_ok=True)
            z.extractall(embed_root)
        return embed_root
    print(f"[runtime] downloading {RUNTIME_URL}")
    with urllib.request.urlopen(RUNTIME_URL, timeout=60) as r:
        data = r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        embed_root.mkdir(parents=True, exist_ok=True)
        z.extractall(embed_root)
    return embed_root


def _enable_import_site(embed_root: Path) -> None:
    """Uncomment ``import site`` in the ._pth so site-packages is loaded."""
    pth = embed_root / _PTH_NAME
    lines = pth.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        if line.strip().startswith("#import site"):
            out.append("import site")
        else:
            out.append(line)
    pth.write_text("\n".join(out) + "\n", encoding="utf-8")


def _write_readme(runtime_dir: Path) -> None:
    (runtime_dir / "README.txt").write_text(
        "atomic-reforge offline runtime (embeddable CPython).\n"
        "Run-only surface: `python.exe -m atomic_reforge.cli run ...` or\n"
        "use the `run_offline.bat` launcher at the bundle root.\n"
        "No `generate`/`report` development capability is bundled.\n"
        f"Interpreter: CPython {RUNTIME_VER} (win_amd64)\n",
        encoding="utf-8",
    )


def build_runtime(
    dest: Path,
    site_packages: Optional[Path] = None,
    embed_root: Optional[Path] = None,
    verbose: bool = True,
) -> dict:
    """Assemble a self-contained runtime directory at ``dest``.

    ``dest`` is the runtime dir that will sit at ``bundle/runtime``. ``python.exe``
    lands directly under ``dest`` (we flatten the embed root into ``dest``).
    Returns a summary dict with package/vendor counts.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    embed = embed_root or download_embed(dest)
    # Flatten embed root into dest (python.exe at dest/python.exe).
    for child in embed.iterdir():
        target = dest / child.name
        if target.exists():
            if target.is_dir() and child.is_dir():
                shutil.rmtree(target)
            elif target.is_file():
                target.unlink()
        shutil.move(str(child), target)
    _enable_import_site(dest)
    _write_readme(dest)

    site = Path(site_packages) if site_packages else _site_packages()
    sp = dest / "Lib" / "site-packages"
    sp.mkdir(parents=True, exist_ok=True)

    vendored = {}
    for name in PURE_PACKAGES:
        src = _resolve_package(name)
        if src is None:
            # try resolving as a C-extension by name (pydantic_core etc.)
            n = _copy_extension(name, site, sp)
            if n:
                vendored[name] = n
            else:
                if verbose:
                    print(f"[runtime] skip {name}: not importable?")
            continue
        if src.is_dir():
            n = _copy_tree(src, sp / name)
        else:
            dst = sp / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            n = 1
        vendored[name] = n

    # atomic_red_team from the ref/ vendored copy (not in venv site-packages).
    at_src = _REF_TEAM_DIR / "atomic_red_team"
    if at_src.is_dir():
        n = _copy_tree(at_src, sp / "atomic_red_team")
        vendored["atomic_red_team (ref)"] = n
    elif verbose:
        print(f"[runtime] warning: {at_src} missing; atomic_red_team not vendored")

    # Our own package: resolve via the editable install's .pth redirect.
    ar_src = _resolve_package("atomic_reforge")
    if ar_src is None:
        # Not importable in this interpreter; fall back to src/ on disk.
        ar_src = Path(__file__).resolve().parent
    if ar_src and ar_src.is_dir():
        n = _copy_tree(ar_src, sp / "atomic_reforge")
        vendored["atomic_reforge (self)"] = n

    python_exe = dest / "python.exe"
    return {
        "runtime_dir": str(dest),
        "python_exe": str(python_exe),
        "packages": vendored,
        "import_site": bool(
            any(
                l.strip() == "import site"
                for l in (dest / _PTH_NAME).read_text(encoding="utf-8").splitlines()
            )
        ),
    }
