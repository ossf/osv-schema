#!/usr/bin/env bash

set -euo pipefail

BASE_URL='https://euvdservices.enisa.europa.eu/api/search'
PAGE_SIZE=100

usage() {
	cat <<'EOF'
usage: dump_euvd.sh [-h] [--query QUERY] out_dir

EUVD dumper.

positional arguments:
	out_dir        Output directory

options:
	-h, --help     show this help message and exit
	--query QUERY  EUVD search query string
EOF
}

query=''
out_dir=''

while [[ $# -gt 0 ]]; do
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		--query)
			if [[ $# -lt 2 ]]; then
				echo 'Missing value for --query' >&2
				exit 1
			fi
			query="$2"
			shift 2
			;;
		--query=*)
			query="${1#*=}"
			shift
			;;
		-*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 1
			;;
		*)
			if [[ -n "$out_dir" ]]; then
				echo 'Only one output directory may be provided.' >&2
				exit 1
			fi
			out_dir="$1"
			shift
			;;
	esac
done

if [[ -z "$out_dir" ]]; then
	usage >&2
	exit 1
fi

mkdir -p "$out_dir"

page=0
count=0
total=''

while true; do
	url="${BASE_URL}?page=${page}&size=${PAGE_SIZE}"
	if [[ -n "$query" ]]; then
		url="${url}&${query}"
	fi

	response=$(curl -fsSL "$url")
	items_count=$(jq '.items | length' <<<"$response")
	if [[ "$items_count" -eq 0 ]]; then
		break
	fi

	if [[ -z "$total" ]]; then
		total=$(jq -r '.total // empty' <<<"$response")
	fi

	mapfile -t items < <(jq -c '.items[]' <<<"$response")
	for item in "${items[@]}"; do
		item_id=$(jq -r '.id' <<<"$item")
		jq '.' <<<"$item" > "$out_dir/${item_id}.json"
		count=$((count + 1))

		if (( count % 500 == 0 )); then
			echo "Up to ${count} advisories."
		fi
	done

	page=$((page + 1))
	if [[ -n "$total" && "$count" -ge "$total" ]]; then
		break
	fi
done

echo "Dumped ${count} advisories."