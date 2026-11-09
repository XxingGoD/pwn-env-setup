#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 sudo ca-certificates curl git
useradd -m -s /bin/bash pwn-test
printf 'pwn-test ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/pwn-env-test
chmod 0440 /etc/sudoers.d/pwn-env-test
PREFIX=/home/pwn-test/pwn-env
runuser -u pwn-test -- env HOME=/home/pwn-test bash "$ROOT/install.sh" --tools radare2 --yes --prefix "$PREFIX"
version="$(runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- r2 -v)"
printf '%s\n' "$version"
grep -q 'radare2 6\.0\.4' <<<"$version"
runuser -u pwn-test -- env HOME=/home/pwn-test bash "$ROOT/install.sh" --tools radare2 --yes --prefix "$PREFIX"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" doctor
