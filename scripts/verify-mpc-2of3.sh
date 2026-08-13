#!/bin/sh

set -eu

if [ "$(uname -s)" != "Linux" ]; then
	echo "verify-mpc-2of3 requires Linux" >&2
	exit 1
fi

export GOWORK=off

verification_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mpc-verify.XXXXXX")
cleanup_verification_output() {
	rm -rf -- "$verification_tmp_dir"
}
trap cleanup_verification_output EXIT HUP INT TERM

run_required_test() {
	package=$1
	pattern=$2
	label=$3
	timeout=$4
	output="$verification_tmp_dir/$label.json"

	if ! go test -json "$package" -run "$pattern" -count=1 -timeout="$timeout" >"$output"; then
		cat "$output"
		echo "mandatory suite failed: $label" >&2
		return 1
	fi
	cat "$output"
	if grep -q '"Action":"skip"' "$output"; then
		echo "mandatory suite skipped: $label" >&2
		return 1
	fi
	if ! grep -Eq '"Action":"pass".*"Test":"' "$output"; then
		echo "mandatory suite unavailable: $label" >&2
		return 1
	fi
}

echo "==> race suite"
go test -race ./... -timeout=30m

echo "==> bounded share inspector fuzz"
fuzz_output="$verification_tmp_dir/inspector-fuzz.json"
if ! go test -json ./internal/shares \
	-run '^$' \
	-fuzz '^FuzzInspectEncodedECDSAKeyMaterial$' \
	-fuzztime=5s >"$fuzz_output"; then
	cat "$fuzz_output"
	echo "mandatory suite failed: inspector-fuzz" >&2
	exit 1
fi
cat "$fuzz_output"
if grep -q '"Action":"skip"' "$fuzz_output"; then
	echo "mandatory suite skipped: inspector-fuzz" >&2
	exit 1
fi
if ! grep -Eq '"Action":"pass".*"Test":"FuzzInspectEncodedECDSAKeyMaterial"' "$fuzz_output"; then
	echo "mandatory suite unavailable: inspector-fuzz" >&2
	exit 1
fi

echo "==> durable preparams subprocess suite"
run_required_test \
	./internal/preparams \
	'^TestCacheCrashBoundariesControlRestartReuse$' \
	preparams-subprocess \
	5m

echo "==> threshold adapter"
run_required_test \
	./internal/tssbnb/utils \
	'^TestBuildParamsConvertsRequiredSignerThresholdForTSSLib$' \
	threshold-adapter \
	2m

echo "==> real 2-of-3 DKG and signing matrix"
run_required_test \
	./tss \
	'^TestMPC2Of3DKGAndEverySigningSubset$' \
	mpc2of3-matrix \
	20m
