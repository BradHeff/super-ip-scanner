#!/usr/bin/env bash
#
# setup.sh — install everything needed to build & run Super IP Scanner from source.
#
# Installs the native build dependencies for your distro, makes sure a Rust
# toolchain (cargo) is present, then installs the JS dependencies (npm install).
#
# Usage:
#   ./setup.sh            # detect distro, install system deps (uses sudo), then npm install
#   ./setup.sh --no-sudo  # skip the system-package step (just run npm install)
#
# After this finishes:
#   npm run tauri:dev     # dev build with Rust hot-reload
#   npm run tauri:build   # native installers under the cargo target dir's bundle/
#
# ─────────────────────────────────────────────────────────────────────────────
# NTFS / FUSE DRIVE NOTE (important if this repo lives on a Windows-shared drive)
# ─────────────────────────────────────────────────────────────────────────────
# If the project sits on an NTFS (ntfs-3g / fuseblk) mount, that filesystem cannot
# execute files, which breaks BOTH build toolchains:
#   * Cargo can't run the build-scripts it compiles  -> `Permission denied (os error 13)`
#   * npm can't exec esbuild/vite                     -> EACCES, install rolls back
# This script detects that case and relocates the exec-sensitive dirs to native FS:
#   * Cargo target/ -> ~/.cache/super-ip-scanner-target  (via src-tauri/.cargo/config.toml)
#   * node_modules  -> bind-mounted from ~/.cache/super-ip-scanner-node_modules
# The bind mount needs sudo and is NOT reboot-persistent; for permanence add to /etc/fstab:
#   /home/$USER/.cache/super-ip-scanner-node_modules  <repo>/node_modules  none  bind  0  0
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NO_SUDO=0
[[ "${1:-}" == "--no-sudo" ]] && NO_SUDO=1

# ── system packages ─────────────────────────────────────────────────────────
# Each package and why it's needed:
#   cargo / rustc ............. build the Rust scan engine (Rust 1.77+)
#   webkit2gtk (4.1) .......... Tauri's webview on Linux
#   gtk3 ...................... GTK shell that hosts the webview
#   (ayatana-)appindicator .... tray / status-area icon
#   librsvg2 .................. renders the SVG app icon
#   libpcap ................... pnet raw-socket ARP backend (Linux ARP path)
#   openssl ................... TLS for DNS-over-TLS / HTTPS deps
#   patchelf .................. required to bundle the Linux AppImage
#   rpm-build (Fedora) ........ build the .rpm installer
#   nodejs / npm .............. frontend toolchain (Node 20+)

install_fedora() {
  echo ">> Fedora/RHEL: installing system packages via dnf"
  $SUDO dnf install -y \
    cargo \
    webkit2gtk4.1-devel \
    gtk3-devel \
    libappindicator-gtk3-devel \
    librsvg2-devel \
    libpcap-devel \
    openssl-devel \
    patchelf \
    rpm-build \
    fuse \
    fuse-libs \
    nodejs \
    npm
  # fuse/fuse-libs provide libfuse.so.2 (FUSE2), needed to RUN AppImages (incl. the
  # linuxdeploy bundler). To BUILD without FUSE2, prefix: APPIMAGE_EXTRACT_AND_RUN=1
}

install_debian() {
  echo ">> Debian/Ubuntu: installing system packages via apt-get"
  $SUDO apt-get update
  $SUDO apt-get install -y \
    cargo \
    rustc \
    libwebkit2gtk-4.1-dev \
    libgtk-3-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    libpcap-dev \
    libssl-dev \
    patchelf \
    libfuse2 \
    nodejs \
    npm
  # libfuse2 (FUSE2) is needed to RUN AppImages. To BUILD where it's absent (e.g.
  # ubuntu-24.04), prefix the build: APPIMAGE_EXTRACT_AND_RUN=1 npm run tauri:build
}

if [[ "$NO_SUDO" -eq 0 ]]; then
  SUDO=""
  [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"

  if   command -v dnf      >/dev/null 2>&1; then install_fedora
  elif command -v apt-get  >/dev/null 2>&1; then install_debian
  else
    echo "!! Unsupported package manager. Install these manually:"
    echo "   cargo, webkit2gtk-4.1, gtk3, appindicator3, librsvg2,"
    echo "   libpcap, openssl, patchelf, nodejs(20+)/npm"
    echo "   then re-run with --no-sudo"
    exit 1
  fi
else
  echo ">> --no-sudo: skipping system packages"
fi

# ── toolchain sanity check ──────────────────────────────────────────────────
# Some distros ship `rustc` and `cargo` in separate packages — fail loudly if
# cargo is still missing rather than dying mid-build.
if ! command -v cargo >/dev/null 2>&1; then
  echo "!! 'cargo' is not on PATH. Install it (Fedora: 'sudo dnf install cargo',"
  echo "   or via rustup: https://rustup.rs) and re-run."
  exit 1
fi
echo ">> cargo:  $(cargo --version)"
echo ">> rustc:  $(rustc --version)"
echo ">> node:   $(node --version)"

# ── NTFS / noexec workaround ────────────────────────────────────────────────
# If the repo is on a filesystem that can't exec files, relocate target/ and
# node_modules onto a native filesystem so the toolchains work.
NATIVE_TARGET="$HOME/.cache/super-ip-scanner-target"
NATIVE_NM="$HOME/.cache/super-ip-scanner-node_modules"
fs_can_exec() {
  local dir="$1" probe="$1/.exectest.$$"
  printf '#!/bin/sh\n' >"$probe" 2>/dev/null || return 1
  chmod +x "$probe" 2>/dev/null
  if "$probe" >/dev/null 2>&1; then rm -f "$probe"; return 0; else rm -f "$probe"; return 1; fi
}

if ! fs_can_exec "$REPO_DIR"; then
  echo ">> repo filesystem cannot exec files (NTFS/FUSE?) — relocating build dirs to native FS"

  # 1) Cargo target-dir -> native, via a local-only .cargo/config.toml (gitignored).
  mkdir -p "$NATIVE_TARGET"
  mkdir -p "$REPO_DIR/src-tauri/.cargo"
  cat >"$REPO_DIR/src-tauri/.cargo/config.toml" <<EOF
# LOCAL-ONLY, do NOT commit. Keeps Cargo's target/ on a native (exec-capable)
# filesystem because this repo lives on an NTFS/FUSE mount that can't exec build-scripts.
[build]
target-dir = "$NATIVE_TARGET"
EOF
  echo "   cargo target-dir -> $NATIVE_TARGET"

  # 2) node_modules -> native, via bind mount (needs sudo; not reboot-persistent).
  mkdir -p "$NATIVE_NM"
  mkdir -p "$REPO_DIR/node_modules"
  if ! mountpoint -q "$REPO_DIR/node_modules"; then
    echo "   bind-mounting node_modules (sudo) ..."
    ${SUDO:-sudo} mount --bind "$NATIVE_NM" "$REPO_DIR/node_modules" \
      && echo "   node_modules -> $NATIVE_NM (bind mount)" \
      || echo "   !! bind mount failed — run manually: sudo mount --bind $NATIVE_NM $REPO_DIR/node_modules"
  else
    echo "   node_modules already bind-mounted"
  fi
fi

# ── JS dependencies ─────────────────────────────────────────────────────────
echo ">> installing JS dependencies (npm install)"
npm install

cat <<'EOF'

✓ Setup complete.

Next steps:
  npm run tauri:dev     # run the app (first Rust build takes 3-5 min)
  npm run tauri:build   # build native installers (.deb/.rpm/.AppImage)
  # If AppImage bundling fails with "failed to run linuxdeploy" (no FUSE2):
  #   APPIMAGE_EXTRACT_AND_RUN=1 npm run tauri:build

Linux note: ARP and ICMP need CAP_NET_RAW. For a dev build, grant it once after
each rebuild (the binary path changes per profile):
  sudo setcap cap_net_raw+ep src-tauri/target/debug/super-ip-scanner
The .deb/.rpm installers set this automatically via their post-install script.
EOF
