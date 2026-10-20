#!/bin/bash
# Runs inside ghcr.io/openwrt/sdk:<arch>-master as the buildbot user.
# /procd is the procd checkout, /artifacts receives bin/ and logs/.

set -e

PACKAGES="${PACKAGES:-procd procd-selinux procd-ujail procd-seccomp uxc}"
JOBS="${JOBS:-$(nproc)}"

group() {
	echo "::group::$1"
}

endgroup() {
	echo "::endgroup::"
}

group "setup.sh"
[ ! -f setup.sh ] || bash setup.sh
endgroup

git config --global --add safe.directory '*'

sed -n \
	-e 's,https://git.openwrt.org/openwrt/,https://github.com/openwrt/,' \
	-e '/^src-git.* base /p' \
	feeds.conf.default > feeds.conf

group "feeds"
cat feeds.conf
./scripts/feeds update base
./scripts/feeds install procd
endgroup

mkdir -p git-src
ln -sfn /procd git-src/procd

makefile="$(readlink -f package/feeds/base/procd/Makefile)"
sed -i \
	-e "s/^PKG_SOURCE_DATE:=.*/PKG_SOURCE_DATE:=$(git -C /procd log -1 --format=%cd --date=format:%Y-%m-%d)/" \
	-e "s/^PKG_SOURCE_VERSION:=.*/PKG_SOURCE_VERSION:=$(git -C /procd rev-parse HEAD)/" \
	-e '/^PKG_MIRROR_HASH:=/d' \
	"$makefile"

for pkg in $PACKAGES; do
	echo "CONFIG_PACKAGE_$pkg=m" >> .config
done

group "make defconfig"
make defconfig </dev/null
endgroup

for pkg in $PACKAGES; do
	grep -qx "CONFIG_PACKAGE_$pkg=[ym]" .config || {
		echo "::error::$pkg cannot be selected for $(sed -n 's/^CONFIG_TARGET_ARCH_PACKAGES="\(.*\)"/\1/p' .config)"
		exit 1
	}
done

RET=0
make -j"$JOBS" BUILD_LOG=1 IGNORE_ERRORS=n package/procd/compile </dev/null || RET=$?

if [ "$RET" -ne 0 ]; then
	for log in $(find logs -path '*/procd/*' -name '*.txt' 2>/dev/null); do
		echo "::group::$log"
		tail -n 200 "$log"
		echo "::endgroup::"
	done
fi

mkdir -p /artifacts/apk
[ ! -d logs ] || cp -a logs /artifacts/
[ "$RET" -eq 0 ] || exit "$RET"

find bin/packages -name '*.apk' -exec cp {} /artifacts/apk/ \;
find bin/targets -path '*/packages/*.apk' ! -name 'kmod-*' ! -name 'kernel-*' \
	-exec cp {} /artifacts/apk/ \;

for pkg in $PACKAGES; do
	apk="$(find /artifacts/apk -name "$pkg-[0-9]*.apk")"
	echo "$pkg $(stat -c %s "$apk")"
done > /artifacts/sizes.txt
