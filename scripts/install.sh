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

url="https://github.com/$repo/releases/download/$version/lb-server-$target.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading lb-server $version for $target"
curl -fsSL "$url" -o "$tmp/lb-server.tar.gz"
tar -C "$tmp" -xzf "$tmp/lb-server.tar.gz"

mkdir -p "$install_dir"
install -m 755 "$tmp/lb-server" "$install_dir/lb-server"

echo "installed to $install_dir/lb-server"
