#!/usr/bin/env bash
# The website in a real browser (headless Chromium, virtual passkey device).
#   bash tests/browser/run.sh        (from the repository; needs Nix and cargo)
set -euo pipefail
cd "$(dirname "$0")/../.."
export NIX_CONFIG="experimental-features = nix-command flakes"
work=$(mktemp -d)
cleanup() { kill "${server:-}" "${browser:-}" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

# Fetched first, so nothing below waits on a download.
chromium=$(nix build --no-link --print-out-paths nixpkgs#chromium)/bin/chromium
py=$(nix build --no-link --print-out-paths --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; python3.withPackages (p: [ p.websockets ])')
cargo build -q

ILIADA_ACCOUNT_LOG_CODES=1 ILIADA_ACCOUNT_DATA="$work/data" NO_COLOR=1 RUST_LOG=info \
  target/debug/iliada-account > "$work/server.log" 2>&1 &
server=$!
"$chromium" --headless=new --no-sandbox --disable-gpu --remote-debugging-port=9222 \
  --user-data-dir="$work/profile" about:blank > "$work/browser.log" 2>&1 &
browser=$!

for _ in $(seq 100); do
  curl -sf http://127.0.0.1:9222/json >/dev/null && curl -sf http://localhost:8480/ >/dev/null && break
  sleep 0.3
done

SHOTS="${SHOTS:-}" "$py/bin/python3" -I tests/browser/passkeys.py "$work/server.log" ||
  { echo "--- server log"; tail -20 "$work/server.log"; exit 1; }
