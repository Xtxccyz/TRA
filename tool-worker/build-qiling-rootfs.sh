#!/bin/sh
# Build a small pinned Linux user-mode rootfs from this image's glibc.
# Do not download Windows ISOs or unpinned third-party rootfs archives.
set -eu

ROOT="${1:-/opt/qiling-rootfs}"
rm -rf "$ROOT"
mkdir -p \
  "$ROOT/bin" \
  "$ROOT/lib" \
  "$ROOT/lib64" \
  "$ROOT/lib/x86_64-linux-gnu" \
  "$ROOT/usr/bin" \
  "$ROOT/usr/lib" \
  "$ROOT/usr/lib/x86_64-linux-gnu" \
  "$ROOT/tmp" \
  "$ROOT/proc" \
  "$ROOT/dev" \
  "$ROOT/etc"

copy_lib() {
  src="$1"
  if [ -e "$src" ]; then
    dest="$ROOT$src"
    mkdir -p "$(dirname "$dest")"
    cp -a "$src" "$dest"
    if [ -L "$src" ]; then
      target="$(readlink -f "$src" || true)"
      if [ -n "$target" ] && [ -e "$target" ]; then
        mkdir -p "$(dirname "$ROOT$target")"
        cp -a "$target" "$ROOT$target"
      fi
    fi
  fi
}

copy_lib /lib64/ld-linux-x86-64.so.2
copy_lib /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
copy_lib /lib/x86_64-linux-gnu/libc.so.6
copy_lib /lib/x86_64-linux-gnu/libpthread.so.0
copy_lib /lib/x86_64-linux-gnu/libdl.so.2
copy_lib /lib/x86_64-linux-gnu/libm.so.6
copy_lib /lib/x86_64-linux-gnu/librt.so.1
copy_lib /lib/x86_64-linux-gnu/libgcc_s.so.1

printf 'root:x:0:0:root:/root:/usr/sbin/nologin\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\n' > "$ROOT/etc/group"
find "$ROOT" -type f -exec sha256sum {} \; | sort | sha256sum | awk '{print $1}' > "$ROOT/ROOTFS.PINNED"
chmod -R a+rX "$ROOT"
cat "$ROOT/ROOTFS.PINNED"
