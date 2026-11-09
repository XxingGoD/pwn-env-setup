# pwn-env-setup

独立的 Linux x86_64 PWN 工具安装器，支持 Ubuntu 22.04、Ubuntu 24.04 与 Arch Linux。交互默认按分类选择，`--list` 与 `--dry-run` 不安装依赖。分类交互界面参考 [SHORiN-KiWATA/shorin-arch-setup](https://github.com/SHORiN-KiWATA/shorin-arch-setup) 的分类/多选体验；未复用其安装代码、配置更改或资源。许可证 AGPL-3.0-or-later。

Ubuntu 22.04、Ubuntu 24.04 与 Arch 官方容器均已完成普通用户真实安装及 smoke 验收。安装器仅安装软件，不迁移个人数据或工作站配置；容器内未使用 privileged、KVM 或额外 ptrace 权限。

## 使用

```sh
bash install.sh --list
bash install.sh --categories debug,rop --dry-run --platform ubuntu22.04
bash install.sh --tools pwntools,ropper --dry-run --platform arch
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

```sh
bash install.sh --all --yes
bash install.sh --categories debug,rop
bash install.sh --tools pwntools,ropper --yes
bash install.sh doctor
~/.local/share/pwn-env/bin/pwn-env exec -- gdb --version
~/.local/share/pwn-env/bin/pwn-env shell
```

不提供未发布仓库地址。建议克隆仓库后从仓库目录运行 `bash install.sh`。安装默认到 `$HOME/.local/share/pwn-env`；`--prefix` 必须为安全的绝对路径。系统包仅在需要时逐条通过 `sudo` 安装；Python/gem/source recipes 使用普通用户权限。没有 `fzf` 时交互以数字菜单呈现；选空或退出不会安装。

程序不修改 shell rc、`~/.gdbinit`、sudoers、用户组、服务、PATH 配置、ASLR、ptrace、sysctl 或包仓库配置。`pwn-env exec` / `pwn-env shell` 只修改子进程环境；交互 shell 仍可能自行读取用户 rc 文件。工具入口位于 `<prefix>/bin`，不会写入 `~/.local/bin`；使用专属的 `pwn-env exec -- ...` 或 `pwn-env shell`。

Python包以项目私有 CPython 3.12 和 uv 管理；兼容 extras 共用 `<prefix>/python/.venv`，angr、unblob 因 `arpy` 固定版本冲突分别使用 `<prefix>/python/.venvs/angr` 和 `.../unblob`。不写系统 site-packages。Frida 不在安装目录中。Ruby gem 源码与独立上游工具由 checksum 锁定。

## 六类软件目录

| 分类 ID | 安装集合 |
|---|---|
| `debug` | GDB、LLDB、strace、AFL++、pwntools、angr、boofuzz、Pwndbg、tmux、socat、netcat |
| `rop` | ROPgadget、ropper、one_gadget 1.9.0 |
| `elf` | binutils、file、patchelf、checksec、elfutils、musl-tools、pyelftools、libc-database（不自动下载 libc 数据） |
| `asm` | GCC/G++、Clang/LLVM/LLD、NASM、radare2、QEMU user/system、capstone、unicorn 2.1.2、keystone、z3 |
| `kernel` | libseccomp、ceccomp core、seccomp-tools、bpftrace、BCC、perf、pahole、kernel-hardening-checker、vmlinux-to-elf |
| `firmware` | binwalk、SquashFS tools、MTD tools、cpio、xz、zstd、lz4、lzop、7zip、unar、sasquatch、unblob、uefi-firmware |

固件范围是静态扫描、解包及 QEMU 仿真工具，不包括 FirmAE 服务栈，也不自动配置 Docker、binfmt、数据库或网络服务。内核工具可能受当前内核头文件、BTF、能力位和容器限制；doctor 只报告，不提升权限或修改内核设置。

unblob 必需提取器：`7z/7zz`、`unar`、`sasquatch`、`unsquashfs`、`debugfs`、`lz4`、`lzop`、`zstd`，以及 Python 依赖提供的 UBI/JFFS2 工具。`fsck.erofs`、`partclone.restore`、`sasquatch-v4be` 未包含在本安装集合；Arch 还缺可选的 `lziprecover`。doctor 分别警告相应格式不可用，不声称支持所有 unblob 格式。运行 unblob 时需使用可写 cwd 或显式指定 `--log PATH`。

Ubuntu 22.04 的官方仓库没有 radare2 候选，安装器使用校验过的上游 6.0.4 源码，普通用户编译到私有前缀；Ubuntu 24.04/Arch 使用原生包。Ubuntu ceccomp 4.3.1 是禁用 eBPF/capture 的 core 构建；Arch 使用官方 ceccomp。perf 的运行内核版本不匹配只报告能力限制。one_gadget 固定为支持旧 Ruby 的 1.9.0，不宣称具有新版 2.x 的全部功能。

首次安装需联网下载私有 uv、CPython、锁定依赖和上游源码，部分依赖需 C/C++/Rust 编译。失败日志位于 `<prefix>/logs`；源码不使用 root 构建。网络或仓库错误会停止，修复环境后重新运行原命令；不自动换版本、启用 AUR、删除包管理器锁或升级系统。

Ubuntu/Arch 包名差异由目录锁定；Arch 只查已启用的官方仓库，不安装 AUR helper。源代码与 release 下载使用 `sources.lock.json` 中的固定版本和 SHA-256。包仓库无候选、校验失败或编译失败时停止，不替换版本、不做系统升级；Arch 同步库过期时提示用户自行 `pacman -Syu`。

参考项目：`SHORiN-KiWATA/shorin-arch-setup`，仅参考分类与交互体验。未复用其执行安装代码、系统配置或桌面资源。
## 已执行的验收

| 平台 | 全选安装 | 再次安装与 doctor | 实际工具 smoke |
|---|---|---|---|
| Ubuntu 22.04 | 通过 | 通过 | 通过 |
| Ubuntu 24.04 | 通过 | 通过 | 通过 |
| Arch `archlinux:base-devel` | 通过 | 通过 | 通过 |

smoke 验证：编译非 PIE ELF；`pwn checksec`、ROPgadget 找到 ret、patchelf 读取解释器、QEMU user 执行；Keystone/Capstone 汇编反汇编、Unicorn EAX=3、Z3 求解、angr 加载 ELF；unblob 解开 tar/gzip/SquashFS 并读回原内容、sasquatch 提取；ceccomp/seccomp-tools 识别 ALLOW；Pwndbg batch 注册 context。原有 `.gdbinit`、shell rc 样例 hash 保持不变。Ubuntu perf 对容器宿主内核版本不匹配只报告警告，未执行 BPF/ptrace/KVM 特权操作。

重现：`docker run --rm -v "$PWD:/src:ro" ubuntu:24.04 bash /src/tests/container-install.sh ubuntu24.04`；另外两个平台分别替换为 `ubuntu:22.04` / `ubuntu22.04` 和 `archlinux:base-devel` / `arch`。脚本只在一次性容器中创建测试用户与测试 sudo 权限，不得直接在宿主机运行。

## 许可证

GNU Affero General Public License v3.0 or later。见 [LICENSE](LICENSE)。
