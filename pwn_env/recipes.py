from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent

_REGISTRY_NAME = ".pwn-env-managed.json"
_SOURCE_MARKER = ".pwn-env-source.json"
_SUBPROJECT_MARKER = ".pwn-env-subproject.json"
_PWNDBG_MARKER = ".pwn-env-recipe.json"

_RUNTIME_LAUNCHER = (
    "#!/bin/sh\n"
    'PREFIX="$(dirname -- "$(realpath -- "$0")")/.."\n'
    'ROOT="$PREFIX/runtime"\n'
    'PWN_ENV_PREFIX="$PREFIX" PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" '
    'PYTHONDONTWRITEBYTECODE=1 exec python3 -B -m pwn_env "$@"\n'
)
_PWNDBG_WRAPPER = (
    "#!/bin/sh\n"
    'PREFIX="$(dirname -- "$(realpath -- "$0")")/.."\n'
    'exec "$PREFIX/pwndbg/bin/pwndbg" "$@"\n'
)
_LIBC_WRAPPER = (
    "#!/bin/sh\n"
    'case "$1" in get|add|find|dump|identify|download) ;; *) '
    "echo 'unsupported libc-db subcommand' >&2; exit 2;; esac\n"
    'subcommand=$1; shift\n'
    'cd "$(dirname -- "$(realpath -- "$0")")/../src/libc-database" || exit\n'
    'if [ "$subcommand" = get ] && [ "$#" -eq 0 ]; then ./get; '
    'rc=$?; [ "$rc" -eq 1 ] && exit 0; exit "$rc"; fi\n'
    'exec ./"$subcommand" "$@"\n'
)

# Files that every locked source build may create.  Anything here is ignored by
# the dirty-source fingerprint so a repaired build is not mistaken for a user
# edit.  Source files with these extensions do not exist in the locked trees.
_COMMON_IGNORE_PARTS = frozenset(
    {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".venv",
        "node_modules",
        "autom4te.cache",
        ".deps",
        ".libs",
        "CMakeFiles",
        ".cache",
        ".ccls-cache",
        "infer-out",
    }
)
_COMMON_IGNORE_NAMES = frozenset(
    {
        "config.log",
        "config.status",
        "stamp-h1",
        "libtool",
        "compile_commands.json",
        "a.out",
        "ninja.exe",
        ".wraplock",
        _SOURCE_MARKER,
        _SUBPROJECT_MARKER,
        _PWNDBG_MARKER,
    }
)
_COMMON_IGNORE_SUFFIXES = (
    ".o",
    ".a",
    ".so",
    ".dylib",
    ".dll",
    ".pyc",
    ".pyo",
    ".lo",
    ".la",
    ".d",
    ".obj",
    ".lib",
    ".exe",
    ".pc",
    ".mo",
    ".gperf",
    ".sdb",
    ".wasm",
    ".dSYM",
)

_R2_SUBPROJECT_DIRS = frozenset(
    {
        "sdb",
        "qjs",
        "capstone",
        "capstone-v4",
        "capstone-v5",
        "capstone-next",
        "binaryninja",
        "v35arm64",
        "v35armv7",
    }
)

_R2_INSTALLED_BINARIES = (
    "r2r",
    "r2pm",
    "ravc2",
    "rax2",
    "rasm2",
    "rabin2",
    "rahash2",
    "radiff2",
    "rapatch2",
    "radare2",
    "rafind2",
    "rarun2",
    "ragg2",
    "r2agent",
    "rasign2",
    "r2",
    "r2p",
    "r2sdb",
)

_R2_BINARIES = frozenset(
    {
        "radare2",
        "r2",
        "r2agent",
        "r2bb",
        "r2blob",
        "r2pm",
        "r2r",
        "r2-indent",
        "r2sdb",
        "rabin2",
        "radiff2",
        "rafind2",
        "ragg2",
        "rahash2",
        "rapatch2",
        "rarun2",
        "rasign2",
        "rasm2",
        "ravc2",
        "rax2",
        "rvc2",
    }
)


_EXPECTED_BIN_NAMES = {
    "ceccomp": {"ceccomp"},
    "sasquatch": {"sasquatch"},
    "libc-database": {"libc-db"},
    "radare2": set(_R2_INSTALLED_BINARIES),
    "one-gadget": {"one_gadget"},
    "seccomp-tools": {"racc", "seccomp-tools"},
    "pwndbg": {"pwndbg"},
    "runtime": {"pwn-env"},
}


class RecipeError(RuntimeError):
    pass


def _as_argv(argv: list[object]) -> list[str]:
    return [os.fspath(item) for item in argv]


def _run(
    argv: list[object],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    allowed: tuple[int, ...] = (0,),
) -> int:
    """Run one argv array, optionally mirroring its output to PWN_ENV_LOG."""

    command = _as_argv(argv)
    run_env = env if env is not None else os.environ.copy()
    log_path = run_env.get("PWN_ENV_LOG")
    if not log_path:
        try:
            result = subprocess.run(command, cwd=cwd, env=env, check=False)
        except OSError as exc:
            raise RecipeError(f"cannot execute {command[0]}: {exc}") from exc
        returncode = result.returncode
    else:
        try:
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
        except OSError as exc:
            raise RecipeError(f"cannot execute {command[0]}: {exc}") from exc
        try:
            with open(log_path, "a", encoding="utf-8") as log:
                log.write("$ " + json.dumps(command, ensure_ascii=False) + "\n")
                assert proc.stdout is not None
                for line in proc.stdout:
                    log.write(line)
                    log.flush()
                    sys.stdout.write(line)
                    sys.stdout.flush()
        except OSError as exc:
            proc.kill()
            raise RecipeError(f"cannot write log {log_path}: {exc}") from exc
        returncode = proc.wait()
    if returncode not in allowed:
        raise RecipeError(f"command failed ({returncode}): {command!r}")
    return returncode


def _capture(
    argv: list[object], *, cwd: Path | None = None, env: dict[str, str] | None = None
) -> str:
    command = _as_argv(argv)
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise RecipeError(f"cannot execute {command[0]}: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RecipeError(
            f"command failed ({result.returncode}): {command!r}"
            + (f": {detail[-1200:]}" if detail else "")
        )
    return result.stdout


def _manifest() -> dict:
    path = ROOT / "sources.lock.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RecipeError(f"cannot read source lock {path}: {exc}") from exc
    sources = data.get("sources") if isinstance(data, dict) else None
    if not isinstance(sources, dict):
        raise RecipeError(f"invalid source lock {path}")
    return sources


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ignore_name(rel: str) -> bool:
    path = PurePosixPath(rel)
    if not path.parts or path.is_absolute() or ".." in path.parts:
        return True
    if any(part in _COMMON_IGNORE_PARTS for part in path.parts):
        return True
    name = path.name
    if name in _COMMON_IGNORE_NAMES:
        return True
    if name.endswith((".tmp", "~")) or ".tmp-" in name:
        return True
    if any(name.endswith(suffix) for suffix in _COMMON_IGNORE_SUFFIXES):
        return True
    if ".so." in name or ".dylib." in name:
        return True
    return False


def _ignore_radare2(rel: str) -> bool:
    if _ignore_name(rel):
        return True
    path = PurePosixPath(rel)
    parts = path.parts
    name = path.name
    if (
        len(parts) >= 2
        and parts[0] == "subprojects"
        and parts[1] in _R2_SUBPROJECT_DIRS
    ):
        return True
    if any(part in {"build", "build_sdb", ".libr", "r2-static", ".wraplock"} for part in parts):
        return True
    if path.as_posix().startswith(("dist/artifacts/", "dist/tarball/", "sys/_work/")):
        return True
    if path.as_posix() in {
        ".test.c",
        "test.c",
        "config-user.mk",
        "plugins.cfg",
        "langs.cfg",
        "libr/config.h",
        "libr/config.mk",
        "libr/include/r_userconf.h",
        "libr/include/r_version.h",
        "libr/include/r_version.h.tmp",
        "libr/flag/d/tags.r2",
        "libr/anal/d/types-windows.sdb.txt",
        "shlr/spp/config.h",
        "shlr/spp/config.mk",
    }:
        return True
    if name.startswith("supported."):
        return True
    if path.as_posix() in {
        "libr/include/sdb",
        "libr/bin/d/dll/dll",
        "libr/arch/p/arm/v35/arch-arm64",
        "libr/arch/p/arm/v35/arch-armv7",
        "libr/egg/p/sc/out",
        "shlr/capstone",
        "shlr/java/out",
        "shlr/spp/spp",
    }:
        return True
    if "d" in parts and name.endswith((".c", ".h", ".gperf", ".out", ".inc")):
        return True
    if parts and parts[0] == "binr" and len(parts) == 3:
        if name == parts[1] or name in _R2_BINARIES or name.endswith(".exe"):
            return True
        if "_CodeSignature" in parts:
            return True
    if "_CodeSignature" in parts:
        return True
    return False


def _ignore_sasquatch(rel: str) -> bool:
    if _ignore_name(rel):
        return True
    return PurePosixPath(rel).name in {"sasquatch", "sasquatch-v4be"}


def _ignore_ceccomp(rel: str) -> bool:
    if _ignore_name(rel):
        return True
    path = PurePosixPath(rel)
    if "build" in path.parts or "CeccompBuild" in path.parts:
        return True
    if path.as_posix() in {"Makefile", "SOURCES.txt", "include/config.h", "include/ebpf"}:
        return True
    return False

def _ignore_libc_database(rel: str) -> bool:
    if _ignore_name(rel):
        return True
    return bool(PurePosixPath(rel).parts) and PurePosixPath(rel).parts[0] in {"db", "libs"}


def _ignore_subproject(name: str, rel: str) -> bool:
    if _ignore_name(rel):
        return True
    path = PurePosixPath(rel)
    parts = path.parts
    filename = path.name
    if any(part in {"build", "out", "Debug", "Release", "build_sdb", ".obj"} for part in parts):
        return True
    if name == "sdb":
        if path.as_posix() in {
            "sdb",
            ".sdb",
            "sdb.exe",
            "src/sdb",
            "src/.sdb",
            "src/sdb_version.h",
            "include/sdb/version.h",
        }:
            return True
        if filename.startswith("libsdb.so") or filename.startswith("libsdb.dylib"):
            return True
    if name.startswith("capstone"):
        if path.as_posix() in {"libcapstone.a", "capstone.pc"}:
            return True
    if name == "qjs":
        if path.as_posix() in {"qjs", "qjs.exe"}:
            return True
    return False


def _ignore_for(tool_id: str) -> Callable[[str], bool]:
    return {
        "radare2": _ignore_radare2,
        "sasquatch": _ignore_sasquatch,
        "ceccomp": _ignore_ceccomp,
        "libc-database": _ignore_libc_database,
    }.get(tool_id, _ignore_name)


def _tree_fingerprint(root: Path, ignore: Callable[[str], bool] | None = None) -> dict[str, str]:
    predicate = ignore or _ignore_name
    result: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directory = Path(dirpath)
        relative_dir = PurePosixPath(directory.relative_to(root).as_posix())
        for name in list(dirnames):
            path = directory / name
            rel = (relative_dir / name).as_posix()
            if predicate(rel):
                dirnames.remove(name)
                continue
            if path.is_symlink():
                result[rel] = "link:" + os.readlink(path)
                dirnames.remove(name)
        for name in filenames:
            path = directory / name
            rel = (relative_dir / name).as_posix()
            if predicate(rel):
                continue
            if path.is_symlink():
                result[rel] = "link:" + os.readlink(path)
            elif path.is_file():
                result[rel] = _sha256(path)
            else:
                raise RecipeError(f"unsupported source entry: {path}")
    return result


def _check_tree(
    root: Path, expected: dict[str, str], ignore: Callable[[str], bool], *, added: bool
) -> None:
    actual = _tree_fingerprint(root, ignore)
    for name, digest in expected.items():
        if actual.get(name) != digest:
            raise RecipeError(f"locked source was modified: {name}")
    if added:
        extra = next((name for name in actual if name not in expected), None)
        if extra is not None:
            raise RecipeError(f"unexpected file in locked source: {extra}")


def _safe_extract(archive: Path, destination: Path) -> Path:
    if destination.is_symlink():
        raise RecipeError(f"unsafe extraction destination: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive, "r:*") as tf:
        members = tf.getmembers()
        seen: set[str] = set()
        link_names: set[str] = set()
        regular_names: set[str] = set()
        normalized: dict[int, str] = {}
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise RecipeError(f"unsafe archive member: {member.name}")
            rel = PurePosixPath(*[part for part in name.parts if part not in {"", "."}])
            relname = rel.as_posix()
            if not relname or relname in seen:
                raise RecipeError(f"duplicate archive member: {member.name}")
            seen.add(relname)
            normalized[id(member)] = relname
            target = (root / Path(*rel.parts)).resolve(strict=False)
            if target != root and root not in target.parents:
                raise RecipeError(f"archive member escapes destination: {member.name}")
            if member.issym():
                link = PurePosixPath(member.linkname)
                link_target = (root / Path(*rel.parent.parts) / Path(member.linkname)).resolve(
                    strict=False
                )
                if link.is_absolute() or (link_target != root and root not in link_target.parents):
                    raise RecipeError(f"unsafe archive link: {member.name}")
                link_names.add(relname)
            elif member.islnk():
                link = PurePosixPath(member.linkname)
                link_rel = PurePosixPath(*[part for part in link.parts if part not in {"", "."}])
                link_target = (root / Path(*link_rel.parts)).resolve(strict=False)
                if (
                    link.is_absolute()
                    or ".." in link.parts
                    or (link_target != root and root not in link_target.parents)
                ):
                    raise RecipeError(f"unsafe archive hard link: {member.name}")
                link_names.add(relname)
            elif member.isfile():
                regular_names.add(relname)
            elif not member.isdir():
                raise RecipeError(f"unsupported special archive member: {member.name}")
        for member in members:
            rel = PurePosixPath(normalized[id(member)])
            if any(
                PurePosixPath(*rel.parts[:index]).as_posix() in link_names
                for index in range(1, len(rel.parts))
            ):
                raise RecipeError(f"archive member is nested below a link: {member.name}")
        regular = [item for item in members if item.isdir() or item.isfile()]
        links = [item for item in members if item.issym() or item.islnk()]
        for member in regular + links:
            if member.islnk():
                target = PurePosixPath(
                    *[
                        part
                        for part in PurePosixPath(member.linkname).parts
                        if part not in {"", "."}
                    ]
                ).as_posix()
                if target not in regular_names:
                    raise RecipeError(
                        f"hard link target is not a regular archive member: {member.name}"
                    )
            tf.extract(member, path=root, set_attrs=True)
    entries = list(root.iterdir())
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return root


def _validate_links(root: Path) -> None:
    resolved_root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + filenames:
            path = Path(dirpath) / name
            if not path.is_symlink():
                continue
            link = os.readlink(path)
            if os.path.isabs(link):
                raise RecipeError(f"absolute symlink in locked source: {path}")
            target = (path.parent / link).resolve(strict=False)
            if target != resolved_root and resolved_root not in target.parents:
                raise RecipeError(f"symlink escapes locked source: {path}")
            if name in dirnames:
                dirnames.remove(name)


def _extract_archive(archive: Path, parent: Path) -> tuple[Path, Path]:
    staging = Path(tempfile.mkdtemp(prefix=".extract-", dir=parent))
    work = staging / "tree"
    work.mkdir()
    try:
        unpacked = _safe_extract(archive, work)
        _validate_links(unpacked)
    except RecipeError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except (OSError, tarfile.TarError) as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise RecipeError(f"cannot extract {archive}: {exc}") from exc
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return staging, unpacked


def _download(source: dict, destination: Path) -> Path:
    url = source.get("url")
    expected = source.get("sha256")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise RecipeError(f"source lock entry is not an HTTPS URL: {url!r}")
    if not isinstance(expected, str) or len(expected) != 64:
        raise RecipeError(f"source lock entry has no valid sha256: {url}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise RecipeError(f"download cache path is not a regular file: {destination}")
        if _sha256(destination) == expected:
            return destination
        destination.unlink()
    fd, tmpname = tempfile.mkstemp(prefix=".download-", dir=destination.parent)
    os.close(fd)
    tmp = Path(tmpname)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "pwn-env-setup"})
        with urllib.request.urlopen(request, timeout=60) as response, tmp.open("wb") as out:
            shutil.copyfileobj(response, out)
        digest = _sha256(tmp)
        if digest != expected:
            raise RecipeError(f"SHA256 mismatch for {url}: got {digest}")
        os.replace(tmp, destination)
        return destination
    except RecipeError:
        tmp.unlink(missing_ok=True)
        raise
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        raise RecipeError(f"download failed for {url}: {exc}") from exc


def _registry_path(prefix: Path) -> Path:
    return prefix / _REGISTRY_NAME


def _load_registry(prefix: Path) -> dict:
    path = _registry_path(prefix)
    if path.is_symlink():
        raise RecipeError(f"managed-bin registry is a symlink: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schema": 1, "bin": {}}
    except (OSError, ValueError) as exc:
        raise RecipeError(f"cannot read managed-bin registry {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RecipeError(f"invalid managed-bin registry {path}")
    entries = data.setdefault("bin", {})
    if not isinstance(entries, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in entries.items()
    ):
        raise RecipeError(f"invalid managed-bin registry {path}")
    return data


def _atomic_write_text(path: Path, text: str) -> None:
    tmp: Path | None = None
    try:
        fd, tmpname = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        tmp = Path(tmpname)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        raise RecipeError(f"cannot write {path}: {exc}") from exc


def _save_registry(prefix: Path, data: dict) -> None:
    path = _registry_path(prefix)
    _atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def _bin_dir(prefix: Path) -> Path:
    bindir = prefix / "bin"
    if bindir.is_symlink() or (bindir.exists() and not bindir.is_dir()):
        raise RecipeError(f"controlled bin path is not a directory: {bindir}")
    bindir.mkdir(parents=True, exist_ok=True)
    return bindir


def _is_rubygems_wrapper(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:8192]
    except OSError:
        return False
    return (
        "This file was generated by RubyGems." in text
        and "Gem.activate_bin_path" in text
    )


def _legacy_managed(prefix: Path, rel: str, tool_id: str) -> bool:
    """Accept a bin entry left by an install that predates the registry.

    This is deliberately narrow: the prefix must carry the project ownership
    marker, the entry must be one of the tool's expected program names, and
    the file must be either recorded in installed.json, a source tree marker
    for the corresponding source recipe, or a RubyGems-generated wrapper.
    Files added by users at other paths, or in a fresh prefix, are never
    adopted.
    """

    marker = prefix / ".pwn-env-setup-owner"
    if marker.is_symlink() or not marker.is_file():
        return False
    try:
        if marker.read_text(encoding="utf-8") != "pwn-env-setup\n":
            return False
    except OSError:
        return False
    expected = _EXPECTED_BIN_NAMES.get(tool_id)
    target = prefix / PurePosixPath(rel)
    if not expected or PurePosixPath(rel).name not in expected:
        return False
    if not (target.is_symlink() or target.is_file()):
        return False
    try:
        state = json.loads((prefix / "installed.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = None
    if isinstance(state, dict):
        tools = state.get("tools")
        if isinstance(tools, dict) and isinstance(tools.get(tool_id), dict):
            return True
    if tool_id in {"one-gadget", "seccomp-tools"}:
        return _is_rubygems_wrapper(target)
    if tool_id in {"ceccomp", "sasquatch", "radare2"}:
        source_marker = prefix / "src" / tool_id / _SOURCE_MARKER
        return source_marker.is_file() and not source_marker.is_symlink()
    return False


def _claim_bin(prefix: Path, rel: str, tool_id: str, *, data: bytes | None = None) -> Path:
    """Claim one controlled bin entry, refusing unmanaged files."""

    path = PurePosixPath(rel)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "bin":
        raise RecipeError(f"invalid controlled bin path: {rel}")
    if len(path.parts) < 2:
        raise RecipeError(f"invalid controlled bin path: {rel}")
    _bin_dir(prefix)
    registry = _load_registry(prefix)
    entries = registry["bin"]
    target = prefix / Path(*path.parts)
    owner = entries.get(rel)
    exists = target.is_symlink() or target.exists()
    if exists:
        if owner == tool_id:
            return target
        if owner is not None and owner != tool_id:
            raise RecipeError(f"controlled bin entry {rel} is owned by {owner}")
        if (
            data is not None
            and target.is_file()
            and not target.is_symlink()
            and target.read_bytes() == data
        ):
            entries[rel] = tool_id
            _save_registry(prefix, registry)
            return target
        if data is None and _legacy_managed(prefix, rel, tool_id):
            entries[rel] = tool_id
            _save_registry(prefix, registry)
            return target
        raise RecipeError(f"refusing to overwrite unmanaged bin entry: {target}")
    if owner is not None and owner != tool_id:
        raise RecipeError(f"controlled bin entry {rel} is owned by {owner}")
    entries[rel] = tool_id
    _save_registry(prefix, registry)
    return target


def _write_bin(prefix: Path, rel: str, content: str, tool_id: str) -> Path:
    data = content.encode("utf-8")
    target = _claim_bin(prefix, rel, tool_id, data=data)
    if target.is_dir() and not target.is_symlink():
        raise RecipeError(f"controlled bin entry is a directory: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp: Path | None = None
    try:
        fd, tmpname = tempfile.mkstemp(prefix=f".{target.name}-", dir=target.parent)
        tmp = Path(tmpname)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, 0o755)
        os.replace(tmp, target)
    except OSError as exc:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        raise RecipeError(f"cannot write controlled bin entry {target}: {exc}") from exc
    return target


def _copy_runtime_entry(source: Path, destination: Path) -> None:
    if source.is_dir() and not source.is_symlink():
        staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}-", dir=destination.parent))
        try:
            staged = staging / "tree"
            shutil.copytree(
                source,
                staged,
                symlinks=True,
                ignore=shutil.ignore_patterns(
                    "__pycache__", "*.pyc", "*.pyo", ".venv", ".pytest_cache", ".mypy_cache"
                ),
            )
            if destination.is_symlink():
                raise RecipeError(f"runtime path is a symlink: {destination}")
            if destination.exists():
                if not destination.is_dir():
                    raise RecipeError(f"runtime path is not a directory: {destination}")
                shutil.rmtree(destination)
            os.replace(staged, destination)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        return
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise RecipeError(f"runtime path is not a regular file: {destination}")
    tmp: Path | None = None
    try:
        fd, tmpname = tempfile.mkstemp(prefix=f".{destination.name}-", dir=destination.parent)
        os.close(fd)
        tmp = Path(tmpname)
        shutil.copy2(source, tmp)
        os.replace(tmp, destination)
    except OSError as exc:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        raise RecipeError(f"cannot copy runtime file {destination}: {exc}") from exc


def _runtime_tree(prefix: Path) -> Path:
    prefix = Path(prefix)
    runtime = prefix / "runtime"
    if runtime.is_symlink():
        raise RecipeError(f"runtime path is a symlink: {runtime}")
    if runtime.exists() and not runtime.is_dir():
        raise RecipeError(f"runtime path is not a directory: {runtime}")
    runtime.mkdir(parents=True, exist_ok=True)
    if runtime.resolve() == ROOT:
        # We are already executing from the runtime copy.  Never delete or copy
        # over the code that is currently running.
        required = [
            runtime / "pwn_env" / "__main__.py",
            runtime / "pwn_env" / "recipes.py",
            runtime / "catalog" / "tools.json",
            runtime / "python" / "pyproject.toml",
            runtime / "python" / "uv.lock",
            runtime / "sources.lock.json",
        ]
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise RecipeError(f"runtime copy is incomplete: {missing[0]}")
    else:
        for name in ("pwn_env", "catalog", "python", "sources.lock.json"):
            source = ROOT / name
            if not source.exists() and not source.is_symlink():
                raise RecipeError(f"project runtime source is missing: {source}")
            _copy_runtime_entry(source, runtime / name)
    _write_bin(prefix, "bin/pwn-env", _RUNTIME_LAUNCHER, "runtime")
    return runtime


def _ensure_uv(prefix: Path, cache: Path) -> Path:
    uvdir = prefix / "uv"
    if uvdir.is_symlink() or (uvdir.exists() and not uvdir.is_dir()):
        raise RecipeError(f"private uv directory is not a directory: {uvdir}")
    uv = uvdir / "uv"
    source = _manifest().get("uv-installer")
    if not isinstance(source, dict):
        raise RecipeError("uv installer lock is missing")
    if uv.is_symlink() or (uv.exists() and not uv.is_file()):
        raise RecipeError(f"private uv path is not a regular file: {uv}")
    if not uv.is_file():
        archive = _download(source, cache / "uv-installer-0.13.6.sh")
        env = os.environ.copy()
        env.update(
            {
                "UV_UNMANAGED_INSTALL": str(prefix / "uv"),
                "UV_NO_MODIFY_PATH": "1",
                "UV_NO_UPDATE_CHECK": "1",
            }
        )
        _run(["sh", archive], env=env)
        if not uv.is_file():
            raise RecipeError("uv bootstrap completed without the expected private uv binary")
    env = os.environ.copy()
    env["UV_NO_UPDATE_CHECK"] = "1"
    version = _capture([uv, "--version"], env=env).strip()
    if not version.startswith("uv 0.13.6"):
        raise RecipeError(f"private uv has unexpected version: {version or 'unknown'}")
    return uv


def _python_venv(prefix: Path, extra: str) -> Path:
    base = prefix / "python"
    return base / ".venvs" / extra if extra in {"angr", "unblob"} else base / ".venv"


def _validate_extra(extra: str) -> None:
    if not extra or extra.startswith("-") or "/" in extra or "\\" in extra:
        raise RecipeError(f"invalid Python extra: {extra}")


def _python_extras(prefix: Path, runtime: Path, extra: str) -> set[str]:
    extras = {extra}
    if extra in {"angr", "unblob"}:
        return extras
    installed: dict = {}
    catalog_tools: dict = {}
    try:
        loaded = json.loads(
            (prefix / "installed.json").read_text(encoding="utf-8")
        ).get("tools", {})
        if isinstance(loaded, dict):
            installed = loaded
    except (OSError, ValueError, AttributeError):
        pass
    try:
        data = json.loads(
            (runtime / "catalog" / "tools.json").read_text(encoding="utf-8")
        )
        if isinstance(data, dict):
            catalog_tools = {
                entry["id"]: entry
                for entry in data.get("tools", [])
                if isinstance(entry, dict) and isinstance(entry.get("id"), str)
            }
    except (OSError, ValueError, KeyError, TypeError):
        pass
    for tool_id, record in installed.items():
        if not isinstance(record, dict) or record.get("recipe") != "python":
            continue
        entry = catalog_tools.get(tool_id)
        if not isinstance(entry, dict):
            continue
        name = entry.get("python_extra")
        if isinstance(name, str) and name not in {"angr", "unblob"}:
            extras.add(name)
    return extras


def _python_recipe(tool: dict, prefix: Path, runtime: Path, cache: Path) -> None:
    extra = tool.get("python_extra")
    if not isinstance(extra, str):
        raise RecipeError(f"Python tool has no extra: {tool.get('id')}")
    _validate_extra(extra)
    envdir = _python_venv(prefix, extra)
    extras = _python_extras(prefix, runtime, extra)
    uv = _ensure_uv(prefix, cache)
    env = os.environ.copy()
    env.update(
        {
            "UV_PROJECT_ENVIRONMENT": str(envdir),
            "UV_CACHE_DIR": str(prefix / "uv-cache"),
            "UV_PYTHON_INSTALL_DIR": str(prefix / "uv-python"),
            "UV_PYTHON_PREFERENCE": "only-managed",
            "UV_NO_UPDATE_CHECK": "1",
        }
    )
    argv: list[object] = [
        uv,
        "sync",
        "--project",
        runtime / "python",
        "--frozen",
        "--no-dev",
        "--python",
        "3.12",
    ]
    for name in sorted(extras):
        argv.extend(["--extra", name])
    _run(argv, env=env)
    if not (envdir / "bin" / "python").is_file():
        raise RecipeError(f"uv sync did not create the expected environment: {envdir}")


def _private_python(prefix: Path, cache: Path) -> Path:
    uv = _ensure_uv(prefix, cache)
    env = os.environ.copy()
    env.update(
        {
            "UV_CACHE_DIR": str(prefix / "uv-cache"),
            "UV_PYTHON_INSTALL_DIR": str(prefix / "uv-python"),
            "UV_PYTHON_PREFERENCE": "only-managed",
            "UV_NO_UPDATE_CHECK": "1",
        }
    )
    _run([uv, "python", "install", "3.12"], env=env)
    found = _capture([uv, "python", "find", "3.12"], env=env).strip()
    path = Path(found)
    managed = (prefix / "uv-python").resolve()
    if not path.is_absolute() or not path.is_file():
        raise RecipeError(f"private Python 3.12 was not found: {found or 'empty result'}")
    if managed not in path.resolve().parents:
        raise RecipeError(f"private Python resolved outside the controlled directory: {path}")
    return path


def _write_json(path: Path, payload: dict) -> None:
    _atomic_write_text(path, json.dumps(payload, sort_keys=True) + "\n")


def _subproject_ignore(name: str) -> Callable[[str], bool]:
    return lambda rel: _ignore_subproject(name, rel)


def _prepare_radare2_subprojects(src: Path, cache: Path, record: dict) -> None:
    subprojects = record.get("subprojects")
    if not isinstance(subprojects, dict) or not subprojects:
        raise RecipeError("radare2 source lock has no pinned subprojects")
    base = src / "subprojects"
    if base.is_symlink() or not base.is_dir():
        raise RecipeError(f"radare2 subprojects directory is missing: {base}")
    for name, source in subprojects.items():
        if (
            not isinstance(name, str)
            or PurePosixPath(name).name != name
            or name in {".", ".."}
            or not isinstance(source, dict)
        ):
            raise RecipeError(f"invalid radare2 subproject lock: {name!r}")
        directory = source.get("directory", name)
        if (
            not isinstance(directory, str)
            or PurePosixPath(directory).name != directory
            or directory in {".", ".."}
        ):
            raise RecipeError(f"invalid radare2 subproject directory: {directory!r}")
        target = base / directory
        ignore = _subproject_ignore(name)
        if target.is_symlink() or target.exists():
            if target.is_symlink() or not target.is_dir():
                raise RecipeError(f"radare2 subproject path is not an owned directory: {target}")
            marker = target / _SUBPROJECT_MARKER
            if marker.is_symlink() or not marker.is_file():
                raise RecipeError(f"radare2 subproject is unowned: {target}")
            try:
                metadata = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise RecipeError(f"cannot read radare2 subproject metadata {marker}: {exc}") from exc
            if metadata.get("sha256") != source.get("sha256"):
                raise RecipeError(f"radare2 subproject archive conflicts with lock: {target}")
            files = metadata.get("files")
            if not isinstance(files, dict):
                raise RecipeError(f"invalid radare2 subproject metadata: {marker}")
            # Build products are ignored, but recorded source files must be untouched.
            _check_tree(target, files, ignore, added=False)
            continue
        archive = _download(source, cache / f"radare2-{name}.tar.gz")
        staging, unpacked = _extract_archive(archive, base)
        try:
            if not unpacked.is_dir():
                raise RecipeError(f"radare2 subproject archive has no directory root: {name}")
            packagefiles = source.get("packagefiles")
            if packagefiles is not None:
                if not isinstance(packagefiles, str):
                    raise RecipeError(f"invalid packagefiles entry for radare2 subproject: {name}")
                package_root = (base / "packagefiles").resolve()
                package_dir = (package_root / packagefiles).resolve()
                if package_root not in package_dir.parents or not package_dir.is_dir():
                    raise RecipeError(f"radare2 packagefiles are missing: {packagefiles}")
                shutil.copytree(
                    package_dir,
                    unpacked,
                    dirs_exist_ok=True,
                    symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
            patches = source.get("patches", [])
            if not isinstance(patches, list):
                raise RecipeError(f"invalid patches entry for radare2 subproject: {name}")
            for patch in patches:
                if not isinstance(patch, str):
                    raise RecipeError(f"invalid patch entry for radare2 subproject: {name}")
                patch_path = (unpacked / path_from_lock(patch)).resolve()
                if patch_path != unpacked.resolve() and unpacked.resolve() not in patch_path.parents:
                    raise RecipeError(f"radare2 patch escapes subproject: {patch}")
                if not patch_path.is_file():
                    raise RecipeError(f"radare2 patch is missing: {patch}")
                _run(["git", "apply", "-p1", patch_path], cwd=unpacked, env=os.environ.copy())
            _validate_links(unpacked)
            files = _tree_fingerprint(unpacked, ignore)
            _write_json(
                unpacked / _SUBPROJECT_MARKER,
                {"sha256": source["sha256"], "files": files},
            )
            os.replace(unpacked, target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)


def path_from_lock(rel: str) -> Path:
    path = PurePosixPath(rel)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise RecipeError(f"unsafe relative path in lock: {rel}")
    return Path(*path.parts)


def _prefix_parts(prefix: Path) -> Path:
    if not prefix.is_absolute():
        raise RecipeError(f"installation prefix is not absolute: {prefix}")
    relative = prefix.relative_to(prefix.anchor)
    return relative if relative.parts else Path()


def _stage_entries(root: Path) -> list[tuple[str, str, Path, str | None]]:
    if root.is_symlink() or not root.is_dir():
        raise RecipeError(f"installation staging tree is missing: {root}")
    entries: list[tuple[str, str, Path, str | None]] = []
    seen: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        directory = Path(dirpath)
        relative_dir = directory.relative_to(root)
        for name in list(dirnames):
            path = directory / name
            rel = PurePosixPath((relative_dir / name).as_posix())
            if path.is_symlink():
                dirnames.remove(name)
                entries.append((rel.as_posix(), "link", path, os.readlink(path)))
                seen.add(rel.as_posix())
            else:
                entries.append((rel.as_posix(), "dir", path, None))
                seen.add(rel.as_posix())
        for name in filenames:
            path = directory / name
            rel = (relative_dir / name).as_posix()
            if rel in seen:
                raise RecipeError(f"duplicate installation entry: {rel}")
            if path.is_symlink():
                entries.append((rel, "link", path, os.readlink(path)))
            elif path.is_file():
                entries.append((rel, "file", path, None))
            else:
                raise RecipeError(f"unsupported installation entry: {path}")
            seen.add(rel)
    entries.sort(key=lambda item: (len(PurePosixPath(item[0]).parts), item[0]))
    return entries


def _refuse_symlink_parents(prefix: Path, target: Path) -> None:
    try:
        relative = target.relative_to(prefix)
    except ValueError as exc:
        raise RecipeError(f"installation target escapes prefix: {target}") from exc
    current = prefix
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise RecipeError(f"installation parent is a symlink: {current}")


def _merge_installed_tree(stage_root: Path, prefix: Path, tool_id: str) -> None:
    entries = _stage_entries(stage_root)
    resolved_prefix = prefix.resolve()
    for rel, kind, source, link in entries:
        path = PurePosixPath(rel)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise RecipeError(f"unsafe installation path: {rel}")
        target = prefix / Path(*path.parts)
        _refuse_symlink_parents(prefix, target)
        if kind == "link":
            assert link is not None
            if os.path.isabs(link):
                raise RecipeError(f"absolute symlink in installation output: {target}")
            resolved_link = (target.parent / link).resolve(strict=False)
            if resolved_link != resolved_prefix and resolved_prefix not in resolved_link.parents:
                raise RecipeError(f"installation symlink escapes prefix: {target}")
    for rel, kind, _source, _link in entries:
        if rel == "bin" or rel.startswith("bin/"):
            if kind in {"file", "link"}:
                _claim_bin(prefix, rel, tool_id)
    for rel, kind, source, link in entries:
        target = prefix / path_from_lock(rel)
        _refuse_symlink_parents(prefix, target)
        if kind == "dir":
            if target.is_symlink():
                target.unlink()
            elif target.exists() and not target.is_dir():
                raise RecipeError(f"installation directory conflicts with file: {target}")
            target.mkdir(parents=True, exist_ok=True)
            continue
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.exists():
            raise RecipeError(f"installation path conflicts with a directory: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if kind == "link":
            assert link is not None
            os.symlink(link, target)
        else:
            shutil.copy2(source, target)


def _install_with_destdir(argv: list[object], *, cwd: Path, prefix: Path, tool_id: str) -> None:
    staging = Path(tempfile.mkdtemp(prefix=".install-", dir=prefix))
    try:
        _run(argv + [f"DESTDIR={staging}"], cwd=cwd, env=os.environ.copy())
        stage_root = staging / _prefix_parts(prefix)
        _merge_installed_tree(stage_root, prefix, tool_id)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _install_sasquatch(src: Path, prefix: Path) -> None:
    staging = Path(tempfile.mkdtemp(prefix=".install-", dir=prefix))
    try:
        _run(
            [
                "make",
                "-C",
                "squashfs-tools",
                "install",
                f"INSTALL_PREFIX={staging}",
            ],
            cwd=src,
            env=os.environ.copy(),
        )
        _merge_installed_tree(staging, prefix, "sasquatch")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _preclaim_source_bins(tool_id: str, prefix: Path) -> None:
    if tool_id == "ceccomp":
        _claim_bin(prefix, "bin/ceccomp", tool_id)
    elif tool_id == "sasquatch":
        _claim_bin(prefix, "bin/sasquatch", tool_id)
    elif tool_id == "libc-database":
        _claim_bin(
            prefix,
            "bin/libc-db",
            tool_id,
            data=_LIBC_WRAPPER.encode("utf-8"),
        )
    elif tool_id == "radare2":
        for name in _R2_INSTALLED_BINARIES:
            _claim_bin(prefix, f"bin/{name}", tool_id)


def _source_recipe(tool_id: str, prefix: Path, cache: Path) -> None:
    locks = _manifest()
    keys = {
        "ceccomp": "ceccomp",
        "sasquatch": "sasquatch",
        "libc-database": "libc-database",
        "radare2": "radare2",
    }
    key = keys.get(tool_id)
    if key is None or key not in locks:
        raise RecipeError(f"source lock unavailable for {tool_id}")
    record = locks[key]
    if not isinstance(record, dict):
        raise RecipeError(f"invalid source lock for {tool_id}")
    expected = record.get("commit") or record.get("ref") or record.get("version")
    if not isinstance(expected, str) or not expected:
        raise RecipeError(f"source lock has no revision for {tool_id}")
    source_sha = record.get("sha256")
    if not isinstance(source_sha, str):
        raise RecipeError(f"source lock has no sha256 for {tool_id}")
    if tool_id in {"ceccomp", "sasquatch", "radare2"} and any(
        character.isspace() for character in os.fspath(prefix)
    ):
        raise RecipeError(f"{tool_id} build cannot use a prefix containing whitespace")
    srcroot = prefix / "src"
    if srcroot.is_symlink():
        raise RecipeError(f"source root is a symlink: {srcroot}")
    if srcroot.exists() and not srcroot.is_dir():
        raise RecipeError(f"source root is not a directory: {srcroot}")
    srcroot.mkdir(parents=True, exist_ok=True)
    src = srcroot / tool_id
    ignore = _ignore_for(tool_id)
    if src.is_symlink():
        raise RecipeError(f"source tree is a symlink: {src}")
    if src.exists():
        if not src.is_dir():
            raise RecipeError(f"source tree is not a directory: {src}")
        marker = src / _SOURCE_MARKER
        if marker.is_symlink() or not marker.is_file():
            raise RecipeError(f"existing source tree is unowned: {src}")
        try:
            metadata = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RecipeError(f"cannot read source metadata {marker}: {exc}") from exc
        if metadata.get("revision") != expected:
            raise RecipeError(f"source ref conflicts with lock: {src}")
        if metadata.get("sha256") != source_sha:
            raise RecipeError(f"source archive conflicts with lock: {src}")
        files = metadata.get("files")
        if not isinstance(files, dict):
            raise RecipeError(f"invalid source metadata: {marker}")
        _check_tree(src, files, ignore, added=True)
        _preclaim_source_bins(tool_id, prefix)
    else:
        _preclaim_source_bins(tool_id, prefix)
        archive = _download(record, cache / f"{key}.tar.gz")
        staging, unpacked = _extract_archive(archive, srcroot)
        try:
            if not unpacked.is_dir():
                raise RecipeError(f"source archive has no directory root: {tool_id}")
            files = _tree_fingerprint(unpacked, ignore)
            _write_json(
                unpacked / _SOURCE_MARKER,
                {
                    "revision": expected,
                    "sha256": source_sha,
                    "files": files,
                },
            )
            os.replace(unpacked, src)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    if tool_id == "ceccomp":
        python = _private_python(prefix, cache)
        _run(
            [
                python,
                src / "configure",
                "--without-doc",
                "--without-i18n",
                "--without-ebpf",
                "--prefix",
                prefix,
            ],
            cwd=src,
            env=os.environ.copy(),
        )
        _run(["make", "-j2"], cwd=src, env=os.environ.copy())
        _install_with_destdir(["make", "install"], cwd=src, prefix=prefix, tool_id=tool_id)
    elif tool_id == "sasquatch":
        _run(["make", "-C", "squashfs-tools", "-j2"], cwd=src, env=os.environ.copy())
        _install_sasquatch(src, prefix)
    elif tool_id == "radare2":
        _prepare_radare2_subprojects(src, cache, record)
        _run(
            [
                src / "configure",
                f"--prefix={prefix}",
                "--with-capstone5",
                "--without-syscapstone",
            ],
            cwd=src,
            env=os.environ.copy(),
        )
        _run(["make", "-j2"], cwd=src, env=os.environ.copy())
        _install_with_destdir(["make", "install"], cwd=src, prefix=prefix, tool_id=tool_id)
    elif tool_id == "libc-database":
        try:
            result = subprocess.run(
                ["bash", "get"],
                cwd=src,
                env=os.environ.copy(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                check=False,
            )
        except OSError as exc:
            raise RecipeError(f"cannot run libc-database get: {exc}") from exc
        output = result.stdout or ""
        if result.returncode != 1 or "Please specify libc categories" not in output:
            raise RecipeError(
                "libc-database get did not list categories"
                + (f": {output[-1200:]}" if output else "")
            )
        _write_bin(prefix, "bin/libc-db", _LIBC_WRAPPER, tool_id)
    else:
        raise RecipeError(f"unsupported source recipe {tool_id!r}")


def _gem_executables(gem: Path) -> list[str]:
    names: list[str] = []
    output = _capture(["gem", "specification", "--local", gem, "executables"])
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("- "):
            name = line[2:].strip().strip("'\"")
            if name:
                names.append(name)
    try:
        with tarfile.open(gem, "r:*") as outer:
            member = outer.getmember("data.tar.gz")
            payload = outer.extractfile(member)
            if payload is not None:
                with tarfile.open(fileobj=payload, mode="r:gz") as data:
                    for item in data.getmembers():
                        path = PurePosixPath(item.name)
                        if (
                            item.isfile()
                            and len(path.parts) == 2
                            and path.parts[0] == "bin"
                        ):
                            names.append(path.name)
    except (KeyError, OSError, tarfile.TarError) as exc:
        raise RecipeError(f"cannot inspect gem executables in {gem}: {exc}") from exc
    return list(dict.fromkeys(names))


def _gem_recipe(tool: dict, prefix: Path, cache: Path) -> None:
    locks = _manifest()
    if tool.get("id") == "one-gadget":
        required = ["bindata", "elftools", "one-gadget"]
    else:
        required = ["racc", "os-gem", "seccomp-tools"]
    gemdir = prefix / "gems"
    if gemdir.is_symlink() or (gemdir.exists() and not gemdir.is_dir()):
        raise RecipeError(f"controlled gem directory is not a directory: {gemdir}")
    gemdir.mkdir(parents=True, exist_ok=True)
    _bin_dir(prefix)
    default_path = _capture(["gem", "env", "path"]).strip()
    env = os.environ.copy()
    env["GEM_HOME"] = str(gemdir)
    paths: list[str] = [str(gemdir)]
    if default_path:
        paths.extend(item for item in default_path.split(os.pathsep) if item)
    if env.get("GEM_PATH"):
        paths.extend(item for item in env["GEM_PATH"].split(os.pathsep) if item)
    env["GEM_PATH"] = os.pathsep.join(dict.fromkeys(paths))
    known = ["one_gadget"] if tool.get("id") == "one-gadget" else ["racc", "seccomp-tools"]
    for executable in known:
        _claim_bin(prefix, f"bin/{executable}", tool["id"])
    planning: list[tuple[Path, list[str]]] = []
    for key in required:
        source = locks.get(key)
        if not isinstance(source, dict):
            raise RecipeError(f"gem lock unavailable: {key}")
        gem = _download(source, cache / f"{key}.gem")
        planning.append((gem, _gem_executables(gem)))
    for _gem, executables in planning:
        for executable in executables:
            _claim_bin(prefix, f"bin/{executable}", tool["id"])
    for gem, executables in planning:
        _run(
            [
                "gem",
                "install",
                "--local",
                "--force",
                "--ignore-dependencies",
                "--no-document",
                "--install-dir",
                gemdir,
                "--bindir",
                prefix / "bin",
                gem,
            ],
            env=env,
        )
        for executable in executables:
            path = prefix / "bin" / executable
            if path.is_symlink():
                continue
            if not path.is_file():
                raise RecipeError(f"gem install did not create the expected entry: {path}")


def _pwndbg(prefix: Path, cache: Path) -> None:
    record = _manifest().get("pwndbg")
    if not isinstance(record, dict):
        raise RecipeError("Pwndbg lock is missing")
    _claim_bin(prefix, "bin/pwndbg", "pwndbg", data=_PWNDBG_WRAPPER.encode("utf-8"))
    destination = prefix / "pwndbg"
    owned = False
    if destination.is_symlink() or destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise RecipeError(f"Pwndbg destination is unowned: {destination}")
        marker = destination / _PWNDBG_MARKER
        if marker.is_symlink() or not marker.is_file():
            raise RecipeError(f"Pwndbg destination is unowned: {destination}")
        try:
            metadata = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RecipeError(f"cannot read Pwndbg metadata {marker}: {exc}") from exc
        if (
            metadata.get("sha256") != record.get("sha256")
            or metadata.get("version") != record.get("version")
        ):
            raise RecipeError(f"Pwndbg destination conflicts with lock: {destination}")
        owned = True
    archive = _download(record, cache / "pwndbg-2026.10.28.tar.xz")
    staging, unpacked = _extract_archive(archive, prefix)
    try:
        if not (unpacked / "bin" / "pwndbg").is_file():
            raise RecipeError("portable Pwndbg archive has unexpected layout")
        _write_json(
            unpacked / _PWNDBG_MARKER,
            {
                "sha256": record.get("sha256"),
                "version": record.get("version"),
                "layout": "portable",
            },
        )
        if owned:
            backup = prefix / f".pwndbg-old-{os.getpid()}"
            os.replace(destination, backup)
            try:
                os.replace(unpacked, destination)
            except Exception:
                os.replace(backup, destination)
                raise
            shutil.rmtree(backup, ignore_errors=True)
        else:
            os.replace(unpacked, destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    _write_bin(prefix, "bin/pwndbg", _PWNDBG_WRAPPER, "pwndbg")


def _plan_entry(
    kind: str,
    *,
    argv: list[object] | tuple[object, ...] = (),
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    **extra: object,
) -> dict:
    entry: dict = {
        "kind": kind,
        "argv": _as_argv(list(argv)),
        "cwd": os.fspath(cwd) if cwd is not None else None,
        "env": dict(env) if env is not None else None,
    }
    entry.update(extra)
    return entry


def _plan_download(source: dict, destination: Path) -> dict:
    url = source.get("url")
    digest = source.get("sha256")
    if not isinstance(url, str) or not isinstance(digest, str):
        raise RecipeError("source lock entry has no URL or sha256")
    return _plan_entry(
        "download",
        url=url,
        sha256=digest,
        path=str(destination),
    )


def _plan_extract(archive: Path, destination: Path, digest: str) -> dict:
    return _plan_entry(
        "extract",
        archive=str(archive),
        sha256=digest,
        destination=str(destination),
    )


def _plan_write(path: Path, content: str, tool_id: str) -> dict:
    return _plan_entry(
        "write",
        path=str(path),
        sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        tool=tool_id,
    )


def _plan_claim(path: Path, tool_id: str) -> dict:
    return _plan_entry("claim-bin", path=str(path), tool=tool_id)


def _plan_uv(prefix: Path, cache: Path, locks: dict) -> list[dict]:
    entries: list[dict] = []
    uvdir = prefix / "uv"
    uv = uvdir / "uv"
    if uvdir.is_symlink() or (uvdir.exists() and not uvdir.is_dir()):
        raise RecipeError(f"private uv directory is not a directory: {uvdir}")
    if uv.is_symlink() or (uv.exists() and not uv.is_file()):
        raise RecipeError(f"private uv path is not a regular file: {uv}")
    source = locks.get("uv-installer")
    if not isinstance(source, dict):
        raise RecipeError("uv installer lock is missing")
    if not uv.is_file():
        entries.append(_plan_download(source, cache / "uv-installer-0.13.6.sh"))
        entries.append(
            _plan_entry(
                "command",
                argv=["sh", cache / "uv-installer-0.13.6.sh"],
                env={
                    "UV_UNMANAGED_INSTALL": str(uvdir),
                    "UV_NO_MODIFY_PATH": "1",
                    "UV_NO_UPDATE_CHECK": "1",
                },
                inherits_environment=True,
            )
        )
    entries.append(
        _plan_entry(
            "command",
            argv=[uv, "--version"],
            env={"UV_NO_UPDATE_CHECK": "1"},
            inherits_environment=True,
            verifies="uv 0.13.6",
        )
    )
    return entries


def _plan_python(tool: dict, prefix: Path, runtime: Path, cache: Path, locks: dict) -> list[dict]:
    extra = tool.get("python_extra")
    if not isinstance(extra, str):
        raise RecipeError(f"Python tool has no extra: {tool.get('id')}")
    _validate_extra(extra)
    envdir = _python_venv(prefix, extra)
    extras = _python_extras(prefix, runtime, extra)
    for name in sorted(extras):
        _validate_extra(name)
    entries = _plan_uv(prefix, cache, locks)
    argv: list[object] = [
        prefix / "uv" / "uv",
        "sync",
        "--project",
        runtime / "python",
        "--frozen",
        "--no-dev",
        "--python",
        "3.12",
    ]
    for name in sorted(extras):
        argv.extend(["--extra", name])
    entries.append(
        _plan_entry(
            "command",
            argv=argv,
            env={
                "UV_PROJECT_ENVIRONMENT": str(envdir),
                "UV_CACHE_DIR": str(prefix / "uv-cache"),
                "UV_PYTHON_INSTALL_DIR": str(prefix / "uv-python"),
                "UV_PYTHON_PREFERENCE": "only-managed",
                "UV_NO_UPDATE_CHECK": "1",
            },
            inherits_environment=True,
            extras=sorted(extras),
        )
    )
    return entries


def _plan_subprojects(src: Path, cache: Path, record: dict) -> list[dict]:
    subprojects = record.get("subprojects")
    if not isinstance(subprojects, dict) or not subprojects:
        raise RecipeError("radare2 source lock has no pinned subprojects")
    entries: list[dict] = []
    for name, source in subprojects.items():
        if not isinstance(source, dict):
            raise RecipeError(f"invalid radare2 subproject lock: {name!r}")
        directory = source.get("directory", name)
        target = src / "subprojects" / str(directory)
        entries.append(_plan_download(source, cache / f"radare2-{name}.tar.gz"))
        entries.append(_plan_extract(cache / f"radare2-{name}.tar.gz", target, str(source.get("sha256", ""))))
        packagefiles = source.get("packagefiles")
        if isinstance(packagefiles, str):
            entries.append(
                _plan_entry(
                    "copy-tree",
                    source=str(src / "subprojects" / "packagefiles" / packagefiles),
                    destination=str(target),
                )
            )
        patches = source.get("patches", [])
        if isinstance(patches, list):
            for patch in patches:
                if isinstance(patch, str):
                    entries.append(
                        _plan_entry(
                            "command",
                            argv=["git", "apply", "-p1", target / path_from_lock(patch)],
                            cwd=target,
                            env=None,
                            inherits_environment=True,
                        )
                    )
    return entries


def _plan_source(tool_id: str, prefix: Path, cache: Path, locks: dict) -> list[dict]:
    keys = {
        "ceccomp": "ceccomp",
        "sasquatch": "sasquatch",
        "libc-database": "libc-database",
        "radare2": "radare2",
    }
    key = keys.get(tool_id)
    if key is None or key not in locks:
        raise RecipeError(f"source lock unavailable for {tool_id}")
    record = locks[key]
    if not isinstance(record, dict):
        raise RecipeError(f"invalid source lock for {tool_id}")
    source_sha = record.get("sha256")
    if not isinstance(source_sha, str):
        raise RecipeError(f"source lock has no sha256 for {tool_id}")
    src = prefix / "src" / tool_id
    archive = cache / f"{key}.tar.gz"
    entries: list[dict] = []
    if tool_id == "ceccomp":
        entries.append(_plan_claim(prefix / "bin" / "ceccomp", tool_id))
    elif tool_id == "sasquatch":
        entries.append(_plan_claim(prefix / "bin" / "sasquatch", tool_id))
    elif tool_id == "libc-database":
        entries.append(_plan_claim(prefix / "bin" / "libc-db", tool_id))
    elif tool_id == "radare2":
        for name in _R2_INSTALLED_BINARIES:
            entries.append(_plan_claim(prefix / "bin" / name, tool_id))
    entries.append(_plan_download(record, archive))
    entries.append(_plan_extract(archive, src, source_sha))
    if tool_id == "radare2":
        entries.extend(_plan_subprojects(src, cache, record))
    staging = "<staging>"
    if tool_id == "ceccomp":
        entries.extend(_plan_uv(prefix, cache, locks))
        uv_env = {
            "UV_CACHE_DIR": str(prefix / "uv-cache"),
            "UV_PYTHON_INSTALL_DIR": str(prefix / "uv-python"),
            "UV_PYTHON_PREFERENCE": "only-managed",
            "UV_NO_UPDATE_CHECK": "1",
        }
        entries.append(
            _plan_entry(
                "command",
                argv=[prefix / "uv" / "uv", "python", "install", "3.12"],
                env=uv_env,
                inherits_environment=True,
            )
        )
        entries.append(
            _plan_entry(
                "command",
                argv=[prefix / "uv" / "uv", "python", "find", "3.12"],
                env=uv_env,
                inherits_environment=True,
                resolves="private-python-3.12",
            )
        )
        entries.append(
            _plan_entry(
                "command",
                argv=[
                    "<private-python-3.12>",
                    src / "configure",
                    "--without-doc",
                    "--without-i18n",
                    "--without-ebpf",
                    "--prefix",
                    prefix,
                ],
                cwd=src,
                env=None,
                inherits_environment=True,
                dynamic=["private-python-3.12"],
            )
        )
        entries.append(
            _plan_entry(
                "command",
                argv=["make", "-j2"],
                cwd=src,
                env=None,
                inherits_environment=True,
            )
        )
        entries.append(
            _plan_entry(
                "command",
                argv=["make", "install", f"DESTDIR={staging}"],
                cwd=src,
                env=None,
                inherits_environment=True,
                dynamic=["staging"],
            )
        )
        entries.append(
            _plan_entry(
                "merge-tree",
                stage=staging,
                destination=str(prefix),
                dynamic=["staging"],
            )
        )
    elif tool_id == "sasquatch":
        entries.append(
            _plan_entry(
                "command",
                argv=["make", "-C", "squashfs-tools", "-j2"],
                cwd=src,
                env=None,
                inherits_environment=True,
            )
        )
        entries.append(
            _plan_entry(
                "command",
                argv=[
                    "make",
                    "-C",
                    "squashfs-tools",
                    "install",
                    f"INSTALL_PREFIX={staging}",
                ],
                cwd=src,
                env=None,
                inherits_environment=True,
                dynamic=["staging"],
            )
        )
        entries.append(
            _plan_entry(
                "merge-tree",
                stage=staging,
                destination=str(prefix),
                dynamic=["staging"],
            )
        )
    elif tool_id == "radare2":
        entries.append(
            _plan_entry(
                "command",
                argv=[
                    src / "configure",
                    f"--prefix={prefix}",
                    "--with-capstone5",
                    "--without-syscapstone",
                ],
                cwd=src,
                env=None,
                inherits_environment=True,
            )
        )
        entries.append(
            _plan_entry(
                "command",
                argv=["make", "-j2"],
                cwd=src,
                env=None,
                inherits_environment=True,
            )
        )
        entries.append(
            _plan_entry(
                "command",
                argv=["make", "install", f"DESTDIR={staging}"],
                cwd=src,
                env=None,
                inherits_environment=True,
                dynamic=["staging"],
            )
        )
        entries.append(
            _plan_entry(
                "merge-tree",
                stage=staging,
                destination=str(prefix),
                dynamic=["staging"],
            )
        )
    elif tool_id == "libc-database":
        entries.append(
            _plan_entry(
                "command",
                argv=["bash", "get"],
                cwd=src,
                env=None,
                inherits_environment=True,
                expected_exit=[1],
            )
        )
        entries.append(_plan_write(prefix / "bin" / "libc-db", _LIBC_WRAPPER, tool_id))
    return entries


def _plan_gem(tool: dict, prefix: Path, cache: Path, locks: dict) -> list[dict]:
    if tool.get("id") == "one-gadget":
        required = ["bindata", "elftools", "one-gadget"]
    else:
        required = ["racc", "os-gem", "seccomp-tools"]
    entries: list[dict] = []
    gemdir = prefix / "gems"
    entries.append(
        _plan_entry(
            "command",
            argv=["gem", "env", "path"],
            env=None,
            inherits_environment=True,
            resolves="system-gem-path",
        )
    )
    known = ["one_gadget"] if tool.get("id") == "one-gadget" else ["racc", "seccomp-tools"]
    for executable in known:
        entries.append(_plan_claim(prefix / "bin" / executable, str(tool.get("id"))))
    for key in required:
        source = locks.get(key)
        if not isinstance(source, dict):
            raise RecipeError(f"gem lock unavailable: {key}")
        gem = cache / f"{key}.gem"
        entries.append(_plan_download(source, gem))
        entries.append(
            _plan_entry(
                "command",
                argv=["gem", "specification", "--local", gem, "executables"],
                env=None,
                inherits_environment=True,
            )
        )
    env = {
        "GEM_HOME": str(gemdir),
        "GEM_PATH": f"{gemdir}:<system-gem-path>",
    }
    for key in required:
        entries.append(
            _plan_entry(
                "command",
                argv=[
                    "gem",
                    "install",
                    "--local",
                    "--force",
                    "--ignore-dependencies",
                    "--no-document",
                    "--install-dir",
                    gemdir,
                    "--bindir",
                    prefix / "bin",
                    cache / f"{key}.gem",
                ],
                env=env,
                inherits_environment=True,
                dynamic=["system-gem-path", "gem-executable-names"],
            )
        )
    return entries


def _plan_pwndbg(prefix: Path, cache: Path, locks: dict) -> list[dict]:
    record = locks.get("pwndbg")
    if not isinstance(record, dict):
        raise RecipeError("Pwndbg lock is missing")
    entries = [
        _plan_claim(prefix / "bin" / "pwndbg", "pwndbg"),
        _plan_download(record, cache / "pwndbg-2026.10.28.tar.xz"),
        _plan_extract(
            cache / "pwndbg-2026.10.28.tar.xz",
            prefix / "pwndbg",
            str(record.get("sha256", "")),
        ),
        _plan_write(prefix / "bin" / "pwndbg", _PWNDBG_WRAPPER, "pwndbg"),
    ]
    return entries


def recipe_plan(tool: dict, platform: str, prefix: Path) -> list[dict]:
    """Return the read-only installation plan for one catalog tool.

    This function never creates directories, downloads files, or runs commands.
    It reads ``sources.lock.json`` plus state files that already exist under the
    prefix.  Each entry has ``kind``, ``argv``, ``cwd`` and ``env`` keys.  Log
    and probe actions belong to the installer and are not part of this plan.

    A few values can only be resolved once the installer runs.  They are
    represented by explicit tokens and listed in the entry's ``dynamic`` key:
    ``<private-python-3.12>`` (from ``uv python find``), ``<staging>`` (unique
    temporary install tree under the prefix), and ``<system-gem-path>`` (from
    ``gem env path``).  Tools that the installer installs from an official
    platform package return an empty plan.
    """

    prefix = Path(os.path.abspath(Path(prefix)))
    locks = _manifest()
    recipe = tool.get("recipe")
    if recipe == "system":
        return []
    if recipe == "source" and tool.get("id") in {"ceccomp", "radare2"}:
        packages = tool.get("packages", {})
        key = "arch" if platform == "arch" else platform
        selected = packages.get(key)
        if selected is None:
            selected = packages.get("ubuntu", [])
        if selected:
            # The installer probes the official package instead of running
            # this source recipe on this platform.
            return []
    runtime = prefix / "runtime"
    cache = prefix / "downloads"
    if recipe == "python":
        return _plan_python(tool, prefix, runtime, cache, locks)
    if recipe == "source":
        return _plan_source(tool["id"], prefix, cache, locks)
    if recipe == "gem":
        return _plan_gem(tool, prefix, cache, locks)
    if recipe == "pwndbg":
        return _plan_pwndbg(prefix, cache, locks)
    raise RecipeError(f"unsupported recipe {recipe!r} for {tool['id']}")


def run_recipe(tool: dict, prefix: Path) -> None:
    prefix = Path(os.path.abspath(Path(prefix)))
    runtime = _runtime_tree(prefix)
    cache = prefix / "downloads"
    if cache.is_symlink() or (cache.exists() and not cache.is_dir()):
        raise RecipeError(f"download cache is not a directory: {cache}")
    cache.mkdir(parents=True, exist_ok=True)
    recipe = tool.get("recipe")
    if recipe == "system":
        return
    if recipe == "python":
        return _python_recipe(tool, prefix, runtime, cache)
    if recipe == "source":
        return _source_recipe(tool["id"], prefix, cache)
    if recipe == "pwndbg":
        return _pwndbg(prefix, cache)
    if recipe == "gem":
        return _gem_recipe(tool, prefix, cache)
    raise RecipeError(f"unsupported recipe {recipe!r} for {tool['id']}")
