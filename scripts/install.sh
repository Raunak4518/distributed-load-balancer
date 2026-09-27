#!/usr/bin/env bash
set -euo pipefail

repo="Raunak4518/distributed-load-balancer"
install_dir="${INSTALL_DIR:-/usr/local/bin}"

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)
    case "$arch" in
      x86_64) target="x86_64-unknown-linux-musl" ;;
      aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
      *)
        echo "unsupported architecture: $arch" >&2
        exit 1
        ;;
    esac
    ;;
  Darwin)
    case "$arch" in
      x86_64) target="x86_64-apple-darwin" ;;
      arm64) target="aarch64-apple-darwin" ;;
      *)
        echo "unsupported architecture: $arch" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "unsupported OS: $os" >&2
    exit 1
    ;;
esac

version="${VERSION:-}"
if [ -z "$version" ]; then
  version="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)"
fi
if [ -z "$version" ]; then
  echo "could not determine the latest release version" >&2
  exit 1
fi

asset="lb-server-$target.tar.gz"
base="https://github.com/$repo/releases/download/$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading lb-server $version for $target"
curl -fsSL "$base/$asset" -o "$tmp/lb-server.tar.gz"

if curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"; then
  expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
  if [ -z "$expected" ]; then
    echo "SHA256SUMS for $version has no entry for $asset" >&2
    exit 1
  fi
  if command -v sha256sum > /dev/null 2>&1; then
    actual="$(sha256sum "$tmp/lb-server.tar.gz" | awk '{ print $1 }')"
  else
    actual="$(shasum -a 256 "$tmp/lb-server.tar.gz" | awk '{ print $1 }')"
  fi
  if [ "$actual" != "$expected" ]; then
    echo "checksum mismatch for $asset: expected $expected, got $actual" >&2
    exit 1
  fi
  echo "verified SHA-256 checksum"
elif [ "${ALLOW_UNVERIFIED:-}" = "1" ]; then
  echo "warning: $version publishes no SHA256SUMS; installing without verification" >&2
else
  echo "$version publishes no SHA256SUMS, so the download cannot be verified." >&2
  echo "Install a release that does, or set ALLOW_UNVERIFIED=1 to proceed anyway." >&2
  exit 1
fi

tar -C "$tmp" -xzf "$tmp/lb-server.tar.gz"

mkdir -p "$install_dir"
install -m 755 "$tmp/lb-server" "$install_dir/lb-server"

echo "installed to $install_dir/lb-server"
