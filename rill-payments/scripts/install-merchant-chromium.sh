#!/bin/sh
# Temporary, diagnostic-only pin for Chromium's completed-stream cancellation bug.
# https://chromium.googlesource.com/chromium/src/+/62473ad0f747e245e514c93e741bb8e168a2a207
set -eu
umask 077
if [ "$(uname -s) $(uname -m)" != "Linux x86_64" ]; then
  echo 'Merchant diagnostic Chromium requires Linux x64' >&2
  exit 1
fi
version='157.0.8090.0'
digest='3ec877f440c1ea393c4f164ce5339dc0fd6b5384184a84b38550a78721c2086c'
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
directory="$repo/tmp/merchant-chromium-$version"
archive="$directory/chrome-linux64.zip"
mkdir -p "$directory"
if [ ! -f "$archive" ]; then
  trap 'rm -f "$archive.partial"' EXIT HUP INT TERM
  curl --http1.1 -fL --connect-timeout 20 --max-time 600 \
    "https://storage.googleapis.com/chrome-for-testing-public/$version/linux64/chrome-linux64.zip" \
    -o "$archive.partial"
  mv "$archive.partial" "$archive"
fi
# Check cached downloads too, and never extract or execute an unchecked archive.
printf '%s  %s\n' "$digest" "$archive" | sha256sum -c - >&2
unzip -qo "$archive" -d "$directory"
executable="$directory/chrome-linux64/chrome"
"$executable" --version | grep -Fx "Google Chrome for Testing $version " >&2
printf '%s\n' "$executable"
