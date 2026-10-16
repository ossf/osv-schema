#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONVERTER="$SCRIPT_DIR/convert_euvd.sh"
OUT_DIR="$SCRIPT_DIR/out"
OSV_DIR="$SCRIPT_DIR/osv"

INPUT_DIR=''
EXPECTED_DIR=''
MODE=''
TOTAL=0

# Verify a required executable is available in PATH.
require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Missing required command: $1" >&2
		exit 1
	fi
}

# Ensure a required file exists before running tests.
require_file() {
	if [[ ! -f "$1" ]]; then
		echo "Missing required file: $1" >&2
		exit 1
	fi
}

# Validate all prerequisites used by this test script.
check_prerequisites() {
	require_command jq
	require_command diff
	require_command mktemp
	require_file "$CONVERTER"
}

# Select fixtures based on what is available in the repository.
select_fixtures() {
	# Otherwise fallback to full dataset fixtures.
	if [[ -d "$OUT_DIR" && -d "$OSV_DIR" ]]; then
		INPUT_DIR="$OUT_DIR"
		EXPECTED_DIR="$OSV_DIR"
		MODE='dataset'
		return
	fi

	echo "Missing fixtures. Expected dataset directories $OUT_DIR and $OSV_DIR." >&2
	exit 1
}

# Convert one input file and compare with expected normalized JSON.
check_conversion() {
	local input_path="$1"
	local expected_path="$2"
	local name
	local tmp_dir
	local actual_path

	name=$(basename "$input_path")
	tmp_dir=$(mktemp -d)
	actual_path="$tmp_dir/$name"

	# Always cleanup temp output directory, including on failures.
	trap 'rm -rf "$tmp_dir"' RETURN

	echo "[$name] Step 1/4: converting input file"

	"$CONVERTER" -o "$tmp_dir" "$input_path"

	# Optional fixture regeneration mode for maintenance.
	if [[ -n "${TESTS_GENERATE:-}" ]]; then
		echo "[$name] Step 2/4: regenerating expected fixture"
		jq '.' "$actual_path" > "$expected_path"
	else
		echo "[$name] Step 2/4: keeping existing expected fixture"
	fi

	echo "[$name] Step 3/4: comparing expected vs actual"

	diff -u \
		<(jq -S . "$expected_path") \
		<(jq -S . "$actual_path")

	echo "[$name] Step 4/4: validation passed"

	TOTAL=$((TOTAL + 1))

	trap - RETURN
	rm -rf "$tmp_dir"
}

# Run compact sample-based checks.
run_sample_tests() {
	check_conversion "$INPUT_DIR/range_with_fixed.json" "$EXPECTED_DIR/range_with_fixed.osv.json"
	check_conversion "$INPUT_DIR/exact_version.json" "$EXPECTED_DIR/exact_version.osv.json"
}

# Run full dataset checks by matching each input file to its expected output.
run_dataset_tests() {
	local input_path
	local name
	local matched=0

	for input_path in "$INPUT_DIR"/*.json; do
		if [[ ! -e "$input_path" ]]; then
			break
		fi
		matched=1
		name=$(basename "$input_path")
		if [[ ! -f "$EXPECTED_DIR/$name" ]]; then
			echo "Missing expected file for $name: $EXPECTED_DIR/$name" >&2
			exit 1
		fi
		check_conversion "$input_path" "$EXPECTED_DIR/$name"
	done

	if [[ "$matched" -eq 0 ]]; then
		echo "No input JSON files found in $INPUT_DIR" >&2
		exit 1
	fi
}

# Entry point: validate setup, select fixture mode, execute checks, print summary.
main() {
	check_prerequisites
	select_fixtures
  run_dataset_tests

	echo "All conversion tests passed (${TOTAL} files)."
}

main "$@"

