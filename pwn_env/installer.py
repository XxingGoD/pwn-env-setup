from dataclasses import dataclass, asdict
import datetime, json, os, shutil, subprocess, sys, time
from pathlib import Path
from .catalog import load_catalog, resolve
from .platforms import package_list

@dataclass
class Action:
    tool_id: str
    kind: str
    argv: list[str]
    cwd: str | None = None
    env: dict[str, str] | None = None
    probe: dict | None = None
    prefix: str | None = None
    steps: list[dict] | None = None

def validate_prefix(prefix):
    p = Path(prefix).expanduser()
    if not p.is_absolute(): raise ValueError("--prefix 必须是绝对路径")
    p = Path(os.path.abspath(p))
    home = Path.home().resolve()
    forbidden = {Path("/"), Path("/usr"), Path("/etc"), Path("/bin"), home}
    resolved = p.resolve(strict=False)
    if resolved in forbidden or any(base in resolved.parents for base in (Path("/usr"), Path("/etc"), Path("/bin"))):
        raise ValueError("不安全的安装目录")
    if p.exists() and any(p.iterdir()):
        marker = p / ".pwn-env-setup-owner"
        if not marker.is_file() or marker.read_text(encoding="utf-8") != "pwn-env-setup\n":
            raise ValueError("现有非空目录没有有效的本项目所有权标记")
    parent = p if p.exists() else p.parent
    while not parent.exists(): parent = parent.parent
    if not os.access(parent, os.W_OK): raise ValueError("安装目录不可写")
    return p

def build_plan(selection, platform, prefix):
    _, tools = load_catalog(); ids = resolve(selection, tools)
    packages = package_list(ids, tools, platform)
    actions = []
    if packages:
        args = (["sudo", "pacman", "-S", "--needed", *packages] if platform == "arch"
                else ["sudo", "apt-get", "install", "--no-install-recommends", *packages])
        actions.append(Action("system-packages", "system", args))
    for tid in ids:
        tool = tools[tid]
        if tool["recipe"] == "system":
            actions.append(Action(tid, "probe", tool.get("probe", {}).get("command", [])))
        elif tool["id"] in {"ceccomp", "radare2"} and tool.get("packages", {}).get(platform, tool.get("packages", {}).get("ubuntu" if platform.startswith("ubuntu") else platform, [])):
            actions.append(Action(tid, "probe", tool.get("probe", {}).get("command", [])))
        else:
            from .recipes import recipe_plan
            steps = recipe_plan(tool, platform, Path(prefix))
            commands = [step for step in steps if step.get("argv")]
            first = commands[0] if commands else {}
            actions.append(Action(tid, tool["recipe"], first.get("argv", []), cwd=first.get("cwd"), env=first.get("env"), steps=steps))
        actions[-1].probe = tool.get("probe", {})
        actions[-1].prefix = str(prefix)
    return actions

def _run(argv, *, env=None, quiet=False):
    run_env = env or os.environ.copy()
    log_path = run_env.get("PWN_ENV_LOG")
    if not log_path:
        try: return subprocess.run(argv, check=False, env=env, stdout=subprocess.DEVNULL if quiet else None).returncode
        except OSError as exc: print(f"执行失败 {argv[0]}: {exc}", flush=True); return 127
    try:
        proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        with open(log_path, "a", encoding="utf-8") as log:
            log.write("$ " + json.dumps(argv, ensure_ascii=False) + "\n")
            for line in proc.stdout:
                log.write(line); log.flush()
                if not quiet: sys.stdout.write(line); sys.stdout.flush()
        return proc.wait()
    except OSError as exc:
        print(f"执行失败 {argv[0]}: {exc}", flush=True); return 127

def _record(prefix, message):
    print(message, flush=True)
    log_path = os.environ.get("PWN_ENV_LOG")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as log: log.write(message + "\n")

def _install_system(packages, platform, yes):
    if not packages: return 0
    if platform == "arch":
        candidates = []
        for package in packages:
            for repository in ("core", "extra"):
                qualified = repository + "/" + package
                result = subprocess.run(["pacman", "-Si", qualified], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                if result.returncode == 0:
                    candidates.append(qualified)
                    break
            else:
                print(f"Arch core/extra 无候选包：{package}；同步库过期时请先手动 pacman -Syu。", flush=True)
                return 1
        missing = []
        for package, qualified in zip(packages, candidates):
            result = subprocess.run(["pacman", "-Q", package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if result.returncode: missing.append(qualified)
        if not missing: return 0
        argv = ["sudo", "pacman", "-S", "--needed"]
        if yes: argv.append("--noconfirm")
        return _run(argv + missing)
    missing = []
    for package in packages:
        result = subprocess.run(["dpkg-query", "-W", "-f=${Status}", package], capture_output=True, text=True, check=False)
        if result.stdout.strip() != "install ok installed": missing.append(package)
    if not missing: return 0
    if _run(["sudo", "apt-get", "update"]): return 1
    if "linux-tools-generic" in missing:
        kernel_package = "linux-tools-" + os.uname().release
        candidate = subprocess.run(["apt-cache", "policy", kernel_package], capture_output=True, text=True, env={**os.environ,"LC_ALL":"C"}, check=False)
        versions = [line.split(":",1)[1].strip() for line in candidate.stdout.splitlines() if line.strip().startswith("Candidate:")]
        if versions and versions[0] != "(none)":
            missing = [kernel_package if package == "linux-tools-generic" else package for package in missing]
    for package in missing:
        result = subprocess.run(["apt-cache", "policy", package], capture_output=True, text=True, env={**os.environ,"LC_ALL":"C"}, check=False)
        candidates = [line.split(":",1)[1].strip() for line in result.stdout.splitlines() if line.strip().startswith("Candidate:")]
        if not candidates or candidates[0] == "(none)":
            print(f"Ubuntu 官方仓库没有候选包：{package}；请检查 universe 是否已启用。", flush=True); return 1
    argv = ["sudo"]
    if yes: argv.extend(["env", "DEBIAN_FRONTEND=noninteractive"])
    argv.extend(["apt-get", "install", "--no-install-recommends"])
    if yes: argv.append("-y")
    return _run(argv + missing)

def _venv(prefix, extra):
    base = Path(prefix)/"python"
    return base/".venvs"/extra if extra in {"angr","unblob"} else base/".venv"

def _tool_env(prefix, tool):
    env = os.environ.copy()
    paths = [str(Path(prefix)/"bin")]
    if tool.get("python_extra"): paths.insert(0, str(_venv(prefix, tool["python_extra"])/"bin"))
    private_lib = str(Path(prefix)/"lib")
    env["LD_LIBRARY_PATH"] = os.pathsep.join([private_lib, env.get("LD_LIBRARY_PATH", "")]).rstrip(os.pathsep)
    paths.extend(str(p/"bin") for p in (Path(prefix)/"python"/".venvs").glob("*") if (p/"bin").is_dir())
    paths.append(str(Path(prefix)/"python"/".venv"/"bin"))
    env["PATH"] = os.pathsep.join(paths + [env.get("PATH", "")])
    env["GEM_HOME"] = str(Path(prefix)/"gems")
    try: default_gems = subprocess.run(["gem", "env", "path"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError): default_gems = os.environ.get("GEM_PATH", "")
    env["GEM_PATH"] = os.pathsep.join([env["GEM_HOME"], *default_gems.split(os.pathsep)])
    return env

def _probe(tool, prefix):
    probe = tool.get("probe", {})
    if "paths" in probe: return any(Path(path).is_file() for path in probe["paths"])
    env = _tool_env(prefix, tool)
    if any(shutil.which(name, path=env["PATH"]) is None for name in probe.get("executables", [])): return False
    if "python" in probe:
        py = _venv(prefix, tool["python_extra"])/"bin"/"python"
        if not py.is_file(): return False
        result = subprocess.run([str(py), "-c", f"import {probe['python']}"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        if result.returncode:
            print(f"Python probe failed for {tool['id']}: {result.stdout[-1200:]}", flush=True)
            return False
        return True
    if "library" in probe:
        import ctypes.util
        return ctypes.util.find_library(probe["library"]) is not None
    command = probe.get("command", [])
    if not command: return False
    if command[0] == "7z" and not shutil.which("7z", path=env["PATH"]): command = ["7zz", *command[1:]]
    candidate = Path(prefix)/"bin"/command[0]
    if candidate.is_file(): command = [str(candidate), *command[1:]]
    try: result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    except OSError: return False
    if result.returncode and tool["id"] not in {"afl++", "netcat", "perf"}:
        print(f"probe {tool['id']} exit={result.returncode}: {result.stdout[-1200:]}", flush=True)
    return result.returncode == 0 or (tool["id"] == "perf" and bool(shutil.which(command[0], path=env["PATH"]))) or (tool["id"] == "netcat" and result.returncode == 1) or (tool["id"] == "afl++" and result.returncode == 1 and "afl-fuzz" in result.stdout[:256].lower())

def _write_state(prefix, tool, source):
    path = Path(prefix)/"installed.json"
    try: state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError): state = {"schema":1,"tools":{}}
    state.setdefault("tools", {})[tool["id"]] = {"recipe":tool["recipe"],"version":tool.get("version","system"),"source":source,"probe":tool.get("probe",{})}
    tmp = path.with_suffix(".json.tmp"); tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False)+"\n",encoding="utf-8"); os.replace(tmp,path)

def execute_plan(actions, yes=False, platform=None, prefix=None):
    if platform is None or prefix is None: return 2
    prefix = validate_prefix(prefix)
    if os.geteuid() == 0:
        print("拒绝以 root 安装；请以普通用户运行 install.sh。", flush=True); return 2
    prefix.mkdir(parents=True, exist_ok=True)
    marker = prefix/".pwn-env-setup-owner"
    if not marker.exists(): marker.write_text("pwn-env-setup\n", encoding="utf-8")
    logs = prefix / "logs"
    logs.mkdir(exist_ok=True)
    log_path = logs / ("install-" + str(time.time_ns()) + ".log")
    log_path.touch()
    os.environ["PWN_ENV_LOG"] = str(log_path)
    package_action = next((a for a in actions if a.kind == "system"), None)
    if package_action:
        rc = _install_system(package_action.argv[4:], platform, yes)
        if rc: return 1
    from .recipes import run_recipe, RecipeError, _runtime_tree
    _runtime_tree(prefix)
    _, tools = load_catalog()
    for action in actions:
        if action.kind == "system": continue
        tool = tools[action.tool_id]
        if _probe(tool, prefix):
            _write_state(prefix, tool, "already-present"); _record(prefix, f"already-present: {action.tool_id}"); continue
        try:
            if action.kind != "probe": run_recipe(tool, prefix)
            if not _probe(tool, prefix): raise RecipeError("安全 probe 未通过")
            _write_state(prefix, tool, "installed"); _record(prefix, f"installed: {action.tool_id}")
        except (RecipeError, OSError, subprocess.SubprocessError) as exc:
            _record(prefix, f"failed: {action.tool_id}: {exc}; log: {log_path}"); return 1
    _record(prefix, f"入口：{prefix / 'bin' / 'pwn-env'}；日志：{log_path}")
    return 0

def print_plan(actions):
    for action in actions: print(json.dumps(asdict(action), ensure_ascii=False))
