#!/usr/bin/env bash

set -euo pipefail

BASE_URL='https://euvdservices.enisa.europa.eu/api/search'

usage() {
	cat <<'EOF'
usage: dump_euvd.sh [-h] [--vendor VENDOR] [--fromDate YYYY-MM-DD] [--toDate YYYY-MM-DD] [--fromEpss 0-100] [--exploited true|false] out_dir

EUVD dumper.

positional arguments:
	out_dir        Output directory

options:
	-h, --help     show this help message and exit
	--vendor VENDOR     Filter advisories by vendor name
	--fromDate DATE     Filter advisories published from date (YYYY-MM-DD)
	--toDate DATE       Filter advisories published up to date (YYYY-MM-DD)
	--fromEpss VALUE    Filter advisories with EPSS from VALUE (0-100)
	--exploited BOOL    Filter advisories by exploitation status (true/false)
EOF
}

vendor=''
from_date=''
to_date=''
from_epss=''
exploited=''
out_dir=''

while [[ $# -gt 0 ]]; do
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		--vendor)
			if [[ $# -lt 2 ]]; then
				echo 'Missing value for --vendor' >&2
				exit 1
			fi
			vendor="$2"
			shift 2
			;;
		--vendor=*)
			vendor="${1#*=}"
			shift
			;;
		--fromDate)
			if [[ $# -lt 2 ]]; then
				echo 'Missing value for --fromDate' >&2
				exit 1
			fi
			from_date="$2"
			shift 2
			;;
		--fromDate=*)
			from_date="${1#*=}"
			shift
			;;
		--toDate)
			if [[ $# -lt 2 ]]; then
				echo 'Missing value for --toDate' >&2
				exit 1
			fi
			to_date="$2"
			shift 2
			;;
		--toDate=*)
			to_date="${1#*=}"
			shift
			;;
		--fromEpss)
			if [[ $# -lt 2 ]]; then
				echo 'Missing value for --fromEpss' >&2
				exit 1
			fi
			from_epss="$2"
			shift 2
			;;
		--fromEpss=*)
			from_epss="${1#*=}"
			shift
			;;
		--exploited)
			if [[ $# -lt 2 ]]; then
				echo 'Missing value for --exploited' >&2
				exit 1
			fi
			exploited="$2"
			shift 2
			;;
		--exploited=*)
			exploited="${1#*=}"
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

urlencode() {
	jq -nr --arg v "$1" '$v|@uri'
}

append_param() {
	local key="$1"
	local value="$2"
	if [[ -n "$value" ]]; then
		params+="&${key}=$(urlencode "$value")"
	fi
}

if [[ -z "$out_dir" ]]; then
	usage >&2
	exit 1
fi

mkdir -p "$out_dir"

page=0
count=0
total=''

while true; do
	params="page=${page}"
	append_param 'vendor' "$vendor"
	append_param 'fromDate' "$from_date"
	append_param 'toDate' "$to_date"
	append_param 'fromEpss' "$from_epss"
	append_param 'exploited' "$exploited"
	url="${BASE_URL}?${params}"

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