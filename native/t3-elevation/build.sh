#!/usr/bin/env bash
# Builds the t3-elevation helper and pam_t3_elevation module into dist/<target>/.
#
#   ./build.sh [--test-server] [target ...]
#
# Targets: aarch64-apple-darwin, aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu
# (default: all three; macOS only on a Mac). Linux builds target glibc 2.17 via
# cargo-zigbuild and link against a stub libpam, so no sysroot is needed.
# `--test-server` also builds the VM test fixture; never ship it.
#
# Needs cargo with the Linux rust-std targets. zig and cargo-zigbuild come from
# nixpkgs when they aren't on PATH.
set -euo pipefail
cd "$(dirname "$0")"

test_server=0
targets=()
for arg in "$@"; do
  case "$arg" in
    --test-server) test_server=1 ;;
    -*) echo "unknown option $arg" >&2; exit 2 ;;
    *) targets+=("$arg") ;;
  esac
done
if [ ${#targets[@]} -eq 0 ]; then
  targets=(aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu)
  [ "$(uname -s)" = Darwin ] && targets=(aarch64-apple-darwin "${targets[@]}")
fi

needs_zig=0
for target in "${targets[@]}"; do
  case "$target" in *linux*) needs_zig=1 ;; esac
done
if [ "$needs_zig" = 1 ] && ! { command -v zig && command -v cargo-zigbuild; } >/dev/null 2>&1; then
  exec nix shell nixpkgs#zig nixpkgs#cargo-zigbuild --command "$0" "$@"
fi

build() {
  local target="$1" out="dist/$1"
  mkdir -p "$out"
  local examples=()
  if [ "$test_server" = 1 ]; then examples=(--features t3-elevation/fixtures --example test-server); fi
  case "$target" in
    *apple-darwin)
      cargo build --release --target "$target" -p t3-elevation -p pam_t3_elevation
      if [ "$test_server" = 1 ]; then cargo build --release --target "$target" -p t3-elevation "${examples[@]}"; fi
      cp "target/$target/release/libpam_t3_elevation.dylib" "$out/pam_t3_elevation.so"
      ;;
    *linux-gnu)
      local arch="${target%%-*}" stub="target/pam-stub/${target%%-*}"
      mkdir -p "$stub"
      zig cc -target "$arch-linux-gnu.2.17" -shared -Wl,-soname,libpam.so.0 -o "$stub/libpam.so" pam/stub/pam_stub.c
      local var
      var="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_RUSTFLAGS"
      export "$var=-L native=$PWD/$stub"
      cargo zigbuild --release --target "$target.2.17" -p t3-elevation -p pam_t3_elevation
      if [ "$test_server" = 1 ]; then cargo zigbuild --release --target "$target.2.17" -p t3-elevation "${examples[@]}"; fi
      cp "target/$target/release/libpam_t3_elevation.so" "$out/pam_t3_elevation.so"
      ;;
    *) echo "unsupported target $target" >&2; exit 2 ;;
  esac
  cp "target/$target/release/t3-elevation" "$out/t3-elevation"
  if [ "$test_server" = 1 ]; then cp "target/$target/release/examples/test-server" "$out/test-server"; fi
  if [[ "$target" == *apple-darwin ]]; then
    for file in "$out"/*; do codesign --force --sign - "$file"; done
  fi
  echo "built $out" >&2
}

for target in "${targets[@]}"; do
  build "$target"
done
