#!/bin/bash
# Runs inside ghcr.io/openwrt/imagebuilder:<target>-master as the buildbot user.
# /packages holds the SDK-built apks, /ci the procd checkout's .github/ci,
# /out receives the images.

set -e

PROFILE="${PROFILE:-generic}"
VERIFY_PACKAGES="${VERIFY_PACKAGES-procd procd-ujail procd-seccomp uxc}"

apk_version() {
	local apk

	apk="$(find /packages -name "$1-[0-9]*.apk" | head -n 1)"
	[ -n "$apk" ] || return 1
	apk="${apk##*/}"
	apk="${apk#"$1"-}"
	echo "${apk%.apk}"
}

echo "::group::setup.sh"
[ ! -f setup.sh ] || bash setup.sh
echo "::endgroup::"

cp /packages/*.apk packages/

files="$(mktemp -d)"
cp -a /ci/files/. "$files/"
mkdir -p "$files/etc/procd-ci"
echo "$SUITES" > "$files/etc/procd-ci/suites"

make image </dev/null \
	PROFILE="$PROFILE" \
	PACKAGES="$PACKAGES" \
	FILES="$files" \
	ROOTFS_FILESYSTEM=squashfs \
	ROOTFS_PARTSIZE="${ROOTFS_PARTSIZE:-256}" \
	BIN_DIR=/out

for pkg in $VERIFY_PACKAGES; do
	ver="$(apk_version "$pkg")" || continue
	grep -qx "$pkg - $ver" /out/*.manifest || {
		echo "::error::image does not contain $pkg $ver from the SDK build"
		exit 1
	}
done
