TAP_N=0
TAP_FAILED=0

tap_ok() {
	TAP_N=$((TAP_N + 1))
	echo "ok $TAP_N - $*"
}

tap_not_ok() {
	TAP_N=$((TAP_N + 1))
	TAP_FAILED=$((TAP_FAILED + 1))
	echo "not ok $TAP_N - $*"
}

tap_check() {
	local desc="$1"
	local ret

	shift
	echo "# $desc: $*" >&2
	"$@" >&2
	ret=$?
	if [ "$ret" -eq 0 ]; then
		tap_ok "$desc"
	else
		echo "# exit status $ret" >&2
		tap_not_ok "$desc"
	fi
}

tap_done() {
	echo "1..$TAP_N"
	[ "$TAP_FAILED" -eq 0 ]
}
