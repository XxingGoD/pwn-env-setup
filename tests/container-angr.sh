#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 sudo
useradd -m -s /bin/bash pwn-test
printf 'pwn-test ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/pwn-env-test
chmod 0440 /etc/sudoers.d/pwn-env-test
PREFIX=/home/pwn-test/pwn-env
runuser -u pwn-test -- env HOME=/home/pwn-test bash "$ROOT/install.sh" --tools angr --yes --prefix "$PREFIX"
cat >/tmp/probe.c <<'EOF'
int main(void) { return 0; }
EOF
gcc -fno-pie -no-pie /tmp/probe.c -o /tmp/probe
runuser -u pwn-test -- "$PREFIX/python/.venvs/angr/bin/python" -c 'import angr,sys; angr.Project(sys.argv[1], auto_load_libs=False)' /tmp/probe
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" doctor
