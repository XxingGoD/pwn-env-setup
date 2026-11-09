from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .catalog import load_catalog
from .installer import _probe, _tool_env, _venv

# The firmware extractors this project promises.  sasquatch-v4be is provided by
# neither the pinned sasquatch build nor the package lists, so it is reported as
# an optional format instead of a broken installation.
UNBLOB_REQUIRED_COMMANDS = (
    "unar",
    "sasquatch",
    "unsquashfs",
    "debugfs",
    "lz4",
    "lzop",
    "zstd",
    "ubireader_extract_files",
    "ubireader_extract_images",
    "jefferson",
)
UNBLOB_7ZIP_COMMANDS = ("7z", "7zz")
UNBLOB_REQUIRED_MODULES = ("ubireader", "jefferson")


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:300]
    return ""


def _resolve(env: dict[str, str], name: str) -> str | None:
    # _tool_env always puts <prefix>/bin and private venv/bin directories first.
    return shutil.which(name, path=env.get("PATH", ""))


def _python_import_failure(prefix: Path, extra: str | None, modules: tuple[str, ...], env: dict[str, str]) -> str | None:
    python = _venv(prefix, extra) / "bin" / "python"
    if not python.is_file():
        return f"私有 Python 环境不存在：{python.parent.parent}"
    result = subprocess.run(
        [str(python), "-c", "import " + ", ".join(modules)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return None
    return _first_line(result.stdout) or f"import {', '.join(modules)} 失败"


def _check_perf(prefix: Path, tool: dict) -> None:
    """Report running-kernel support without failing a present binary.

    Ubuntu can install linux-tools-generic while the modules/tools for the
    running kernel are absent.  A missing/capability-limited perf is a manual
    system action, not something doctor is allowed to repair.
    """
    env = _tool_env(prefix, tool)
    command = _resolve(env, "perf")
    if not command:
        return
    try:
        result = subprocess.run(
            [command, "--version"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except OSError as exc:
        print(f"WARN perf: 无法执行 perf --version：{exc}；请手动安装与运行内核匹配的 linux-tools")
        return
    output = (result.stdout or "").strip()
    lowered = output.lower()
    unavailable = (
        result.returncode != 0
        or "not found for kernel" in lowered
        or "perf not found" in lowered
    )
    if unavailable:
        detail = _first_line(output)
        print(
            "WARN perf: 二进制已安装，但运行内核对应的 perf 不可用"
            + (f"（{detail}）" if detail else "")
            + "；请手动安装匹配的 linux-tools-*，doctor 不修改系统。"
        )


def _parse_unblob_dependencies(output: str) -> set[str]:
    missing: set[str] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1] == "✗":
            missing.add(parts[-2])
    return missing


def _check_unblob(prefix: Path, tool: dict) -> list[str]:
    failures: list[str] = []
    env = _tool_env(prefix, tool)

    for name in UNBLOB_REQUIRED_COMMANDS:
        if not _resolve(env, name):
            print(f"FAIL unblob extractor missing: {name}")
            failures.append("unblob")
    if not any(_resolve(env, name) for name in UNBLOB_7ZIP_COMMANDS):
        print("FAIL unblob extractor missing: 7z/7zz")
        failures.append("unblob")

    import_error = _python_import_failure(prefix, "unblob", UNBLOB_REQUIRED_MODULES, env)
    if import_error:
        print(f"FAIL unblob Python 传递依赖导入失败：{import_error}")
        failures.append("unblob")

    try:
        result = subprocess.run(
            ["unblob", "--show-external-dependencies"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except OSError as exc:
        print(f"FAIL unblob 无法执行外部依赖检查：{exc}")
        return [*dict.fromkeys([*failures, "unblob"])]

    output = result.stdout or ""
    reported_missing = _parse_unblob_dependencies(output)
    optional_missing = sorted(reported_missing - set(UNBLOB_REQUIRED_COMMANDS) - set(UNBLOB_7ZIP_COMMANDS))
    for name in optional_missing:
        print(f"WARN unblob 可选提取器未安装：{name}（可选格式不可用）")

    # unblob exits 1 when any optional extractor is absent.  Only fail when the
    # command itself broke or when a promised extractor is missing.
    if result.returncode and not reported_missing:
        print(f"FAIL unblob 外部依赖检查失败：{_first_line(output) or 'exit=' + str(result.returncode)}")
        failures.append("unblob")

    return list(dict.fromkeys(failures))


def doctor(prefix: Path) -> int:
    prefix = Path(prefix)
    state_file = prefix / "installed.json"
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print("没有本项目安装记录；请先运行安装器。")
        return 2
    except (OSError, ValueError) as exc:
        print(f"无法读取安装记录 {state_file}：{exc}")
        return 2

    tools_state = state.get("tools")
    if not isinstance(tools_state, dict):
        print(f"安装记录格式无效：{state_file}")
        return 2

    _, tools = load_catalog()
    failures: list[str] = []
    unblob_ok = False
    for tid in sorted(tools_state):
        tool = tools.get(tid)
        if tool is None:
            print(f"FAIL {tid}: 安装记录中的工具不在当前目录中")
            failures.append(tid)
            continue
        if _probe(tool, prefix):
            print(f"OK {tid}")
            if tid == "perf":
                _check_perf(prefix, tool)
            if tid == "unblob":
                unblob_ok = True
        else:
            print(f"FAIL {tid}: 安全探测未通过")
            failures.append(tid)

    if unblob_ok:
        failures.extend(_check_unblob(prefix, tools["unblob"]))

    if "libc-database" in tools_state:
        print("说明 libc-database：仅安装程序；libc 数据需显式运行 libc-db download/get/add，空数据库不算安装失败。")
    if "gdb" in tools_state or "pwndbg" in tools_state:
        print("说明：安装器未修改用户 ~/.gdbinit；Pwndbg 请通过 <prefix>/bin/pwndbg 显式使用。")

    if failures:
        print("doctor: 有工具检查未通过")
        return 1
    print("doctor: 已选工具全部通过检查")
    return 0
