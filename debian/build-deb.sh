#!/bin/bash
#
# Build firewallo .deb package
# Usage: ./debian/build-deb.sh
#
set -e

SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(grep '"version"' "$SRCDIR/etc/firewallo/firewallo.json" | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
PKGNAME="firewallo_${VERSION}_${ARCH}"
PKGDIR="/tmp/${PKGNAME}"

echo "Building firewallo ${VERSION} for ${ARCH}..."

# Build binaries
echo "Compiling..."
make -C "$SRCDIR" clean
make -C "$SRCDIR" all

# Create package structure
rm -rf "$PKGDIR"
mkdir -p "$PKGDIR/DEBIAN"
mkdir -p "$PKGDIR/usr/local/sbin"
mkdir -p "$PKGDIR/etc/firewallo"
mkdir -p "$PKGDIR/usr/local/share/firewallo/web"
mkdir -p "$PKGDIR/lib/systemd/system"
mkdir -p "$PKGDIR/usr/share/doc/firewallo"

# Copy binaries
install -m 755 "$SRCDIR/build/firewallo" "$PKGDIR/usr/local/sbin/firewallo"
install -m 755 "$SRCDIR/build/firewallo-web" "$PKGDIR/usr/local/sbin/firewallo-web"

# Copy config (preserve existing on upgrade)
install -m 644 "$SRCDIR/etc/firewallo/firewallo.json" "$PKGDIR/etc/firewallo/firewallo.json"

# Copy web frontend
cp -r "$SRCDIR/web/"* "$PKGDIR/usr/local/share/firewallo/web/"

# Copy systemd services
install -m 644 "$SRCDIR/systemd/firewallo.service" "$PKGDIR/lib/systemd/system/"
install -m 644 "$SRCDIR/systemd/firewallo-web.service" "$PKGDIR/lib/systemd/system/"

# Copy docs
install -m 644 "$SRCDIR/README.md" "$PKGDIR/usr/share/doc/firewallo/"
install -m 644 "$SRCDIR/LICENSE" "$PKGDIR/usr/share/doc/firewallo/"
install -m 644 "$SRCDIR/CHANGELOG.md" "$PKGDIR/usr/share/doc/firewallo/"

# Copy DEBIAN files
sed "s/^Architecture:.*/Architecture: ${ARCH}/" "$SRCDIR/debian/control" > "$PKGDIR/DEBIAN/control"
sed -i "s/^Version:.*/Version: ${VERSION}/" "$PKGDIR/DEBIAN/control"
install -m 644 "$SRCDIR/debian/conffiles" "$PKGDIR/DEBIAN/conffiles"
install -m 755 "$SRCDIR/debian/postinst" "$PKGDIR/DEBIAN/postinst"
install -m 755 "$SRCDIR/debian/prerm" "$PKGDIR/DEBIAN/prerm"

# Set permissions
find "$PKGDIR" -type d -exec chmod 0755 {} \;
find "$PKGDIR/usr/local/share" -type f -exec chmod 0644 {} \;

# Build .deb
echo "Packaging..."
dpkg-deb --build "$PKGDIR" "$SRCDIR/${PKGNAME}.deb"

# Cleanup
rm -rf "$PKGDIR"

echo ""
echo "Package built: ${PKGNAME}.deb"
echo "Install with: sudo apt install ./${PKGNAME}.deb"
