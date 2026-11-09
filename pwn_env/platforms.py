from __future__ import annotations
import platform as host_platform
from pathlib import Path

SUPPORTED = {"ubuntu22.04", "ubuntu24.04", "arch"}

def detect_platform(os_release: dict, machine: str) -> str:
    if machine not in {"x86_64", "amd64"}: raise ValueError("仅支持 Linux x86_64")
    if os_release.get("ID") == "arch": return "arch"
    if os_release.get("ID") == "ubuntu" and os_release.get("VERSION_ID") in {"22.04", "24.04"}:
        return "ubuntu" + os_release["VERSION_ID"]
    raise ValueError("仅支持 Ubuntu 22.04/24.04 与 Arch Linux")

def detect_host() -> str:
    if host_platform.system() != "Linux": raise ValueError("仅支持 Linux")
    data = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1); data[k] = v.strip().strip('"')
    except OSError: pass
    return detect_platform(data, host_platform.machine())

def package_list(ids, tools, platform_id):
    key = "arch" if platform_id == "arch" else platform_id
    result = []
    needs_build = False
    for tid in ids:
        tool = tools[tid]
        packages = tool.get("packages", {})
        selected_key = key if key in packages else ("ubuntu" if key.startswith("ubuntu") else key)
        result.extend(packages.get(selected_key, []))
        build_packages = tool.get("build_packages", {})
        build_key = key if key in build_packages else ("ubuntu" if key.startswith("ubuntu") else key)
        result.extend(build_packages.get(build_key, []))
        needs_build = needs_build or tool["recipe"] != "system"
    if needs_build:
        result.extend(["ca-certificates", "curl", "git", "base-devel" if key == "arch" else "build-essential", "pkgconf" if key == "arch" else "pkg-config", "python" if key == "arch" else "python3"])
    return list(dict.fromkeys(result))
