#!/bin/bash
# vm-run.sh <target> <image dir> <output dir>
# Boots the image, waits for the guest to power itself off and unpacks the
# results the guest wrote to the marker disk.

set -e

TARGET="$1"
IMAGES="$2"
OUT="$3"
MAGIC=PROCD-CI-RESULTS
ROOTFS_SIZE="${ROOTFS_SIZE:-256M}"

mkdir -p "$OUT"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

image() {
	local img

	img="$(find "$IMAGES" -name "$1" | head -n 1)"
	[ -n "$img" ] || { echo "::error::no image matching $1" >&2; exit 1; }
	case "$img" in
	*.gz) gzip -dc "$img" > "$work/${2:-disk.img}" || [ $? -eq 2 ] ;;
	*) cp "$img" "$work/${2:-disk.img}" ;;
	esac
	echo "$work/${2:-disk.img}"
}

rootfs() {
	local disk

	disk="$(image "$1")"
	truncate -s "$ROOTFS_SIZE" "$disk"
	echo "$disk"
}

kvm() {
	[ -w /dev/kvm ] && [ "$(uname -m)" = x86_64 ] && echo -enable-kvm
}

truncate -s 64M "$work/results.img"
printf '%s' "$MAGIC" | dd of="$work/results.img" conv=notrunc status=none

case "$TARGET" in
x86-64)
	disk="$(image '*-generic-squashfs-combined.img.gz')"
	set -- qemu-system-x86_64 $(kvm) -m 2048 -smp 2 \
		-drive "file=$disk,if=virtio,format=raw" \
		-drive "file=$work/results.img,if=virtio,format=raw"
	;;
x86-generic)
	disk="$(image '*-generic-squashfs-combined.img.gz')"
	set -- qemu-system-i386 $(kvm) -m 2048 -smp 2 \
		-drive "file=$disk,if=virtio,format=raw" \
		-drive "file=$work/results.img,if=virtio,format=raw"
	;;
armsr-armv8)
	kernel="$(image '*-generic-kernel.bin' kernel.bin)"
	disk="$(rootfs '*-generic-squashfs-rootfs.img.gz')"
	set -- qemu-system-aarch64 -M virt -cpu cortex-a57 -m 1024 -smp 2 \
		-kernel "$kernel" -append "root=/dev/vda rootwait console=ttyAMA0" \
		-drive "file=$disk,if=virtio,format=raw" \
		-drive "file=$work/results.img,if=virtio,format=raw"
	;;
armsr-armv7)
	kernel="$(image '*-generic-kernel.bin' kernel.bin)"
	disk="$(rootfs '*-generic-squashfs-rootfs.img.gz')"
	set -- qemu-system-arm -M virt -cpu cortex-a15 -m 1024 -smp 2 \
		-kernel "$kernel" -append "root=/dev/vda rootwait console=ttyAMA0" \
		-drive "file=$disk,if=virtio,format=raw" \
		-drive "file=$work/results.img,if=virtio,format=raw"
	;;
malta-be|malta-le)
	kernel="$(image '*-generic-kernel.bin' kernel.bin)"
	disk="$(rootfs '*-squashfs-rootfs.img.gz')"
	qemu=qemu-system-mips
	[ "$TARGET" = malta-be ] || qemu=qemu-system-mipsel
	set -- "$qemu" -M malta -m 256 \
		-kernel "$kernel" -append "root=/dev/sda rootwait console=ttyS0" \
		-drive "file=$disk,if=ide,format=raw" \
		-drive "file=$work/results.img,if=ide,format=raw"
	;;
*)
	echo "::error::unknown target $TARGET" >&2
	exit 1
	;;
esac

echo "::group::console"
"$@" -nographic -no-reboot -nic none 2>&1 | tee "$OUT/console.log"
echo "::endgroup::"

grep -q 'reboot: Power down' "$OUT/console.log" || {
	echo "::error::guest did not power down cleanly"
	exit 1
}

tar -xf "$work/results.img" -C "$OUT" || {
	echo "::error::guest wrote no results"
	exit 1
}
