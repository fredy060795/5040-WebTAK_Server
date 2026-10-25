#!/bin/sh
# WebTAK Server installer for Raspberry Pi and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/fredy060795/5040-WebTAK_Server/main/install/install.sh | sudo sh
#
# Downloads the right program for this device, installs it as a service that starts automatically
# and opens the firewall (ufw) if it is active. Running it again updates to the latest version.
set -e

REPO="fredy060795/5040-WebTAK_Server"
VERSION="${WTS_VERSION:-latest}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo:  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install/install.sh | sudo sh"
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64)          ARCH=amd64 ;;
  aarch64|arm64)         ARCH=arm64 ;;
  armv6l|armv7l|armhf)   ARCH=armv6 ;;   # all 32-bit Raspberry Pi models
  *) echo "Sorry, this processor ($(uname -m)) is not supported."; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/$REPO/releases/latest/download/webtak-server-linux-$ARCH"
else
  URL="https://github.com/$REPO/releases/download/$VERSION/webtak-server-linux-$ARCH"
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
echo "Downloading WebTAK Server ($ARCH) …"
if command -v curl >/dev/null 2>&1; then
  curl -fL --progress-bar -o "$TMP" "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -q --show-progress -O "$TMP" "$URL"
else
  echo "Neither curl nor wget is installed:  sudo apt install curl"
  exit 1
fi
chmod +x "$TMP"
"$TMP" version
"$TMP" install
