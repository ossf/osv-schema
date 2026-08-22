#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TEST_DIR="$SCRIPT_DIR/testdata"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

check_conversion() {
  local name="$1"
  local tmp_dir
  local actual_path
  local expected_path

  tmp_dir=$(mktemp -d)
  actual_path="$tmp_dir/${name}.json"
  expected_path="$TEST_DIR/${name}.osv.json"

  "$SCRIPT_DIR/convert_euvd.sh" -o "$tmp_dir" "$TEST_DIR/${name}.json"

  if [[ -n "${TESTS_GENERATE:-}" ]]; then
    jq '.' "$actual_path" > "$expected_path"
  fi

  diff -u \
    <(jq -S . "$expected_path") \
    <(jq -S . "$actual_path")

  rm -rf "$tmp_dir"
}

main() {
  require_command jq
  require_command diff
  require_command mktemp

  check_conversion 'range_with_fixed'
  check_conversion 'exact_version'
}

main "$@"