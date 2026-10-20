#!/bin/bash
# evaluate.sh <results dir> <target> <suites...>
# TAP suites pass with a complete plan and no failure; the oci suite is
# compared per test against .github/ci/oci-expected/<target>.txt.

RESULTS="$1"
TARGET="$2"
shift 2

CI_DIR="$(dirname "$0")/../ci"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
failed=0

tap_evaluate() {
	local out="$RESULTS/$1.out"
	local plan total notok

	[ -f "$out" ] || { echo "::error::$TARGET $1: no output"; return 1; }

	plan="$(sed -n 's/^1\.\.\([0-9]*\)$/\1/p' "$out")"
	total="$(grep -c '^\(not \)\?ok ' "$out")"
	notok="$(grep -c '^not ok ' "$out")"
	echo "| $1 | $((total - notok))/$total |" >> "$SUMMARY"

	grep '^not ok ' "$out" | while read -r line; do
		echo "::error::$TARGET $1: $line"
	done
	[ -n "$plan" ] && [ "$plan" -eq "$total" ] && [ "$notok" -eq 0 ] || {
		echo "::group::$1 stderr"
		cat "$RESULTS/$1.err"
		echo "::endgroup::"
		return 1
	}
}

oci_counts() {
	awk '
		/^### / { name = $2; ok[name] += 0; notok[name] += 0; next }
		/^ok / { ok[name]++ }
		/^not ok / { notok[name]++ }
		END { for (n in ok) print n, ok[n], notok[n] }
	' "$1" | sort
}

oci_evaluate() {
	local expected="$CI_DIR/oci-expected/$TARGET.txt"
	local out="$RESULTS/oci.out"
	local name ok notok exp_ok exp_notok total_ok=0 total_notok=0 ret=0

	[ -f "$out" ] || { echo "::error::$TARGET oci: no output"; return 1; }
	oci_counts "$out" > "$RESULTS/oci-counts.txt"

	while read -r name ok notok; do
		total_ok=$((total_ok + ok))
		total_notok=$((total_notok + notok))
	done < "$RESULTS/oci-counts.txt"
	echo "| oci | $total_ok ok, $total_notok not ok |" >> "$SUMMARY"

	[ -f "$expected" ] || {
		echo "::error::$TARGET oci: no $expected, counts are in oci-counts.txt"
		return 1
	}

	while read -r name exp_ok exp_notok; do
		read -r ok notok <<< "$(awk -v n="$name" '$1 == n { print $2, $3 }' "$RESULTS/oci-counts.txt")"
		if [ -z "$ok" ]; then
			echo "::error::$TARGET oci $name: test did not run"
			ret=1
		elif [ "$ok" -lt "$exp_ok" ] || [ "$notok" -gt "$exp_notok" ]; then
			echo "::error::$TARGET oci $name: $ok ok, $notok not ok, expected $exp_ok ok, $exp_notok not ok"
			ret=1
		elif [ "$ok" -ne "$exp_ok" ] || [ "$notok" -ne "$exp_notok" ]; then
			echo "::notice::$TARGET oci $name: improved to $ok ok, $notok not ok, update $expected"
		fi
	done < "$expected"

	return "$ret"
}

echo "### $TARGET" >> "$SUMMARY"
echo "| suite | result |" >> "$SUMMARY"
echo "| :--- | :---: |" >> "$SUMMARY"

for suite in "$@"; do
	case "$suite" in
	oci) oci_evaluate || failed=1 ;;
	*) tap_evaluate "$suite" || failed=1 ;;
	esac
done

exit "$failed"
