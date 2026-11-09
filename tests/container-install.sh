#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${1:?platform identifier required}"
PREFIX=/home/pwn-test/pwn-env

if [[ "${PWN_ENV_REUSE:-0}" != 1 ]]; then
if [[ "$PLATFORM" == ubuntu* ]]; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 sudo ca-certificates curl git
  useradd -m -s /bin/bash pwn-test
  printf 'pwn-test ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/pwn-env-test
  chmod 0440 /etc/sudoers.d/pwn-env-test
else
  pacman -Syu --noconfirm
  pacman -S --needed --noconfirm sudo git curl ca-certificates python
  useradd -m -s /bin/bash pwn-test
  printf 'pwn-test ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/pwn-env-test
  chmod 0440 /etc/sudoers.d/pwn-env-test
fi
fi

printf 'set confirm off\n' >/home/pwn-test/.gdbinit
printf 'user bash rc sentinel\n' >>/home/pwn-test/.bashrc
chown -R pwn-test:pwn-test /home/pwn-test
before_gdb="$(sha256sum /home/pwn-test/.gdbinit | cut -d' ' -f1)"
before_bash="$(sha256sum /home/pwn-test/.bashrc | cut -d' ' -f1)"
before_sudoers="$(sha256sum /etc/sudoers /etc/sudoers.d/pwn-env-test)"
runuser -u pwn-test -- env HOME=/home/pwn-test bash "$ROOT/install.sh" --all --yes --prefix "$PREFIX"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" doctor
runuser -u pwn-test -- env HOME=/home/pwn-test bash "$ROOT/install.sh" --all --yes --prefix "$PREFIX"

TMP="$(mktemp -d)"
cat >"$TMP/fixture.c" <<'EOF'
int main(void) { return 0; }
EOF
gcc -fno-pie -no-pie "$TMP/fixture.c" -o "$TMP/fixture"
chown -R pwn-test:pwn-test "$TMP"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- pwn checksec "$TMP/fixture"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- ROPgadget --binary "$TMP/fixture" --only ret --depth 2
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- patchelf --print-interpreter "$TMP/fixture"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- qemu-x86_64 "$TMP/fixture"
mkdir "$TMP/source" "$TMP/out" "$TMP/tar-out" "$TMP/gzip-out"
printf pwn-env-smoke >"$TMP/source/hello.txt"
tar -C "$TMP/source" -czf "$TMP/sample.tar.gz" hello.txt
gzip -c "$TMP/source/hello.txt" >"$TMP/sample.gz"
mksquashfs "$TMP/source" "$TMP/sample.sqfs" -noappend -quiet
chown -R pwn-test:pwn-test "$TMP"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- unblob -p 1 --log "$TMP/tar.log" --extract-dir "$TMP/tar-out" "$TMP/sample.tar.gz"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- unblob -p 1 --log "$TMP/gzip.log" --extract-dir "$TMP/gzip-out" "$TMP/sample.gz"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- unblob -p 1 --log "$TMP/squash.log" --extract-dir "$TMP/out" "$TMP/sample.sqfs"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- sasquatch -d "$TMP/sas-out" "$TMP/sample.sqfs"
python3 -c 'import pathlib,sys; root=pathlib.Path(sys.argv[1]); expected=b"pwn-env-smoke"; [(lambda matches: (_ for _ in ()).throw(AssertionError(str(folder))) if not matches else None)([p for p in (root/folder).rglob("*") if p.is_file() and p.read_bytes()==expected]) for folder in ("tar-out","gzip-out","out","sas-out")]' "$TMP"
printf '\006\000\000\000\000\000\377\177' >"$TMP/allow.bpf"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- ceccomp disasm "$TMP/allow.bpf" >"$TMP/ceccomp.out"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- seccomp-tools disasm "$TMP/allow.bpf" >"$TMP/seccomp.out"
grep -q ALLOW "$TMP/ceccomp.out"
grep -q ALLOW "$TMP/seccomp.out"
grep -q 'ret' < <(runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- ROPgadget --binary "$TMP/fixture" --only ret --depth 2)
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- pwndbg --batch -ex 'help context' -ex quit
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- libc-db get
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" exec -- python "$ROOT/tests/runtime-smoke.py"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/python/.venvs/angr/bin/python" -c 'import angr,sys; angr.Project(sys.argv[1], auto_load_libs=False)' "$TMP/fixture"
runuser -u pwn-test -- env HOME=/home/pwn-test "$PREFIX/bin/pwn-env" doctor
[[ "$before_gdb" == "$(sha256sum /home/pwn-test/.gdbinit | cut -d' ' -f1)" ]]
[[ "$before_bash" == "$(sha256sum /home/pwn-test/.bashrc | cut -d' ' -f1)" ]]
[[ "$before_sudoers" == "$(sha256sum /etc/sudoers /etc/sudoers.d/pwn-env-test)" ]]
if find "$PREFIX" -type f -print0 | xargs -0 grep -EIl '/home/[^/]+/CtfTools/' >"$TMP/host-path-matches"; then
  cat "$TMP/host-path-matches" >&2
  echo 'workstation home path leaked into prefix' >&2
  exit 1
fi
printf 'platform smoke passed: %s\n' "$PLATFORM"
