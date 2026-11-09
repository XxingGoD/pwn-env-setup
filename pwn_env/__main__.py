import argparse, os, shutil, subprocess, sys
from .catalog import load_catalog, select_categories, CatalogError
from .platforms import detect_host
from .installer import validate_prefix, build_plan, print_plan, execute_plan
from .doctor import doctor

def _prefix():
    return os.environ.get("PWN_ENV_PREFIX", os.path.expanduser("~/.local/share/pwn-env"))

def _environment(prefix):
    from pathlib import Path
    env = os.environ.copy()
    base = Path(prefix)/"python"
    venvs = [p for p in [base/".venv", *(base/".venvs").glob("*")] if (p/"bin"/"python").is_file()]
    bins = [str(Path(prefix)/"bin")] + [str(p/"bin") for p in venvs]
    env["PATH"] = os.pathsep.join(bins + [env.get("PATH", "")])
    private_lib = str(Path(prefix)/"lib")
    env["LD_LIBRARY_PATH"] = os.pathsep.join([private_lib, env.get("LD_LIBRARY_PATH", "")]).rstrip(os.pathsep)
    env["GEM_HOME"] = str(Path(prefix)/"gems")
    try: default_gems = subprocess.run(["gem", "env", "path"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError): default_gems = os.environ.get("GEM_PATH", "")
    env["GEM_PATH"] = os.pathsep.join([env["GEM_HOME"], *default_gems.split(os.pathsep)])
    if (base/".venv"/"bin"/"python").is_file(): env["VIRTUAL_ENV"] = str(base/".venv")
    elif len(venvs) == 1: env["VIRTUAL_ENV"] = str(venvs[0])
    else: env.pop("VIRTUAL_ENV", None)
    return env

CATEGORIES = ["debug", "rop", "elf", "asm", "kernel", "firmware"]
def _numbers(answer, entries):
    indexes = [int(value.strip()) for value in answer.split(",")]
    if any(index < 1 or index > len(entries) for index in indexes): raise ValueError("无效菜单编号")
    return [entries[index - 1] for index in dict.fromkeys(indexes)]

def _fzf_select(entries, title, default_all=False):
    rows = [f"{entry['id']}\t{entry.get('name', entry['id'])} — {entry.get('description', '')}" for entry in entries]
    argv = ["fzf", "--multi", "--delimiter=\t", "--with-nth=2..", "--prompt=" + title,
            "--header=Tab 多选 / Ctrl-A 全选 / Enter 确定 / Esc 退出", "--bind=ctrl-a:select-all", "--expect=esc"]
    if default_all: argv.append("--bind=start:select-all,ctrl-a:select-all")
    result = subprocess.run(argv, input="\n".join(rows), stdout=subprocess.PIPE, text=True, check=False)
    if result.returncode == 130: raise KeyboardInterrupt
    if result.returncode: return []
    lines = result.stdout.splitlines()
    if lines and lines[0] == "esc": return []
    return [line.split("\t",1)[0] for line in lines[1:] if line]

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "doctor":
        p = argparse.ArgumentParser(); p.add_argument("--prefix", default=_prefix())
        a = p.parse_args(argv[1:])
        try: return doctor(validate_prefix(a.prefix))
        except (ValueError, OSError) as exc: print(f"错误：{exc}", file=sys.stderr); return 2
    if argv and argv[0] == "exec":
        if len(argv) < 3 or argv[1] != "--": return 2
        try: os.execvpe(argv[2], argv[2:], _environment(_prefix()))
        except FileNotFoundError: print(f"命令不存在：{argv[2]}", file=sys.stderr); return 127
        except PermissionError: print(f"命令不可执行：{argv[2]}", file=sys.stderr); return 126
    if argv and argv[0] == "shell":
        if len(argv) != 1: return 2
        shell = os.environ.get("SHELL") or "/bin/bash"
        if not os.path.isfile(shell) or not os.access(shell, os.X_OK): shell = "/bin/bash"
        print("仅修改该 shell 子进程环境；shell 仍可能读取用户自己的 rc 文件。", file=sys.stderr)
        return os.execvpe(shell, [shell], _environment(_prefix()))
    p = argparse.ArgumentParser(description="PWN 工具分类安装器")
    p.add_argument("--list", action="store_true"); p.add_argument("--categories")
    p.add_argument("--tools"); p.add_argument("--all", action="store_true")
    p.add_argument("--yes", action="store_true"); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--platform", choices=["ubuntu22.04", "ubuntu24.04", "arch"])
    p.add_argument("--prefix", default=_prefix())
    a = p.parse_args(argv)
    data, tools = load_catalog()
    if a.list:
        for c in data["categories"]:
            print(f"{c['id']} — {c['name']}: {c['description']}")
            for t in data["tools"]:
                if t["category"] == c["id"]: print(f"  {t['id']}: {t['description']} [{t['recipe']}]")
        return 0
    if bool(a.categories) + bool(a.tools) + bool(a.all) > 1: p.error("--categories、--tools、--all 互斥")
    if a.platform and not a.dry_run: p.error("--platform 仅可用于 --dry-run")
    try:
        if a.categories: selection = select_categories([x.strip() for x in a.categories.split(",")])
        elif a.tools: selection = [x.strip() for x in a.tools.split(",")]
        elif a.all: selection = CATEGORIES and [t["id"] for t in data["tools"]]
        else:
            if not sys.stdin.isatty(): print("无交互终端且未选择工具", file=sys.stderr); return 2
            if shutil.which("fzf"):
                try:
                    selected = _fzf_select(data["categories"], "分类 > ")
                    selection = []
                    for category in selected:
                        members = [t for t in data["tools"] if t["category"] == category]
                        selection.extend(_fzf_select(members, category + " 工具 > ", default_all=True))
                except KeyboardInterrupt: return 130
                if not selection: return 0
            else:
                print("分类：" + ", ".join(f"{i+1}:{c['id']}" for i,c in enumerate(data["categories"])))
                try: answer = input("输入分类编号（逗号分隔，a全选，q退出）：").strip()
                except KeyboardInterrupt: return 130
                if answer == "q" or not answer: return 0
                try: selected = CATEGORIES if answer == "a" else _numbers(answer, CATEGORIES)
                except (ValueError, IndexError): p.error("无效分类编号")
                selection = []
                for category in selected:
                    members = [t for t in data["tools"] if t["category"] == category]
                    for i, tool in enumerate(members): print(f"{i+1}: {tool['name']} — {tool['description']} [{tool['recipe']}；源码编译/大型框架请留意首次下载]")
                    try: choice = input("输入编号（逗号分隔，a全部，Enter全部，q退出）：").strip()
                    except KeyboardInterrupt: return 130
                    if choice == "q": return 0
                    if choice in {"", "a"}: selection.extend(t["id"] for t in members)
                    else:
                        try: selection.extend(member["id"] for member in _numbers(choice, members))
                        except (ValueError, IndexError): p.error("无效工具编号")
        from .catalog import resolve
        selection = resolve(selection, tools)
        platform = a.platform or detect_host()
        prefix = validate_prefix(a.prefix)
        actions = build_plan(selection, platform, prefix)
        print_plan(actions)
        if a.dry_run: return 0
        if not selection: return 0
        if not a.yes:
            if not sys.stdin.isatty(): print("非交互安装需显式 --yes", file=sys.stderr); return 2
            try: approved = input("确认执行以上计划？[y/N] ").strip().lower() == "y"
            except KeyboardInterrupt: return 130
            if not approved: return 0
        return execute_plan(actions, a.yes, platform, prefix)
    except (CatalogError, ValueError, OSError) as exc:
        print(f"错误：{exc}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
