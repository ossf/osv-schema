#!/usr/bin/env bash

set -euo pipefail

EUVB_API_URL_PREFIX='https://euvdservices.enisa.europa.eu/api/enisaid?id='

usage() {
	cat <<'EOF'
usage: convert_euvd.sh [-h] -o OUTPUT_DIR input_files [input_files ...]

EUVD to OSV converter.

positional arguments:
	input_files           Input files

options:
	-h, --help            show this help message and exit
	-o OUTPUT_DIR, --output-dir OUTPUT_DIR
												Output directory
EOF
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Missing required command: $1" >&2
		exit 1
	fi
}

convert_date() {
	local value="$1"
	local normalized
	if [[ -z "$value" ]]; then
		printf '%s' "$value"
		return
	fi

	normalized=$(sed -E 's/, / /g' <<<"$value")

	if date -u -d "$normalized" '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then
		date -u -d "$normalized" '+%Y-%m-%dT%H:%M:%SZ'
		return
	fi

	printf '%s' "$value"
}

convert_file() {
	local input_path="$1"
	local output_path="$2"
	local euvd_id
	local published
	local modified

	euvd_id=$(jq -r '.id' "$input_path")
	published=$(convert_date "$(jq -r '.datePublished // empty' "$input_path")")
	modified=$(convert_date "$(jq -r '.dateUpdated // empty' "$input_path")")

	jq \
		--arg euvd_id "$euvd_id" \
		--arg euvd_api_url "${EUVB_API_URL_PREFIX}${euvd_id}" \
		--arg published "$published" \
		--arg modified "$modified" \
		'
		def trim:
			gsub("^\\s+|\\s+$"; "");

		def dedupe:
			reduce .[] as $item ([]; if index($item) == null then . + [$item] else . end);

		def split_lines:
			if . == null or . == "" then [] else split("\n") | map(select(length > 0)) end;

		def ref_type:
			if contains("nvd.nist.gov/vuln/detail/") or contains("github.com/advisories/") or contains("/security/advisories/") or contains("euvd.enisa.europa.eu/") or contains("euvdservices.enisa.europa.eu/api/enisaid") then "ADVISORY"
			elif contains("/commit/") or contains("/pull/") or contains("/compare/") then "FIX"
			else "WEB"
			end;

		def parse_exact_versions($product_version):
			if ($product_version | length) == 0 or (($product_version | ascii_downcase) == "n/a") or (($product_version | ascii_downcase) == "unknown") or ($product_version | test("\\s|,")) then [] else [$product_version] end;

		def parse_version_ranges($product_version):
			if ($product_version | length) == 0 then []
			else
				($product_version | trim) as $normalized
				| ($normalized | ascii_downcase) as $lowered
				| if $lowered == "n/a" or $lowered == "unknown" then []
					elif ($lowered | startswith("before and including ")) then
						[{type: "ECOSYSTEM", events: [{introduced: "0"}, {last_affected: ($normalized | sub("^[Bb]efore and including\\s+"; ""))}]}]
					elif ($lowered | startswith("before ")) then
						[{type: "ECOSYSTEM", events: [{introduced: "0"}, {fixed: ($normalized | sub("^[Bb]efore\\s+"; ""))}]}]
					else
						($normalized | split(",") | map(trim) | map(select(length > 0))) as $parts
						| if ($parts | length) == 0 then []
							else ($parts | map(if test("^(<=|>=|=|<|>)\\s*(.+)$") then capture("^(?<operator><=|>=|=|<|>)\\s*(?<version>.+)$") | .version |= trim else null end)) as $specs
							| if ($specs | any(. == null)) then []
								elif (($specs | map(select(.operator == "=")) | length) > 0 and ($specs | length) == 1) then []
								else ($specs | reduce .[] as $spec ({events: [], has_lower: false};
										if $spec.operator == ">=" or $spec.operator == ">" then
											{events: (.events + [{introduced: $spec.version}]), has_lower: true}
										elif $spec.operator == "<" then
											{events: (.events + [{fixed: $spec.version}]), has_lower: .has_lower}
										elif $spec.operator == "<=" then
											{events: (.events + [{last_affected: $spec.version}]), has_lower: .has_lower}
										else .
										end)) as $parsed
								| if ($parsed.events | length) == 0 then []
									else [{type: "ECOSYSTEM", events: ((if (($parsed.has_lower | not) and ($specs | any(.operator == "<" or .operator == "<="))) then [{introduced: "0"}] else [] end) + $parsed.events)}]
									end
								end
							end
					end
			end;

		def build_affected:
			(.product.name // "") as $name
			| (.product.vendor.name // null) as $vendor
			| ((.product_version // "") | trim) as $product_version
			| if $name == "" or (($name | ascii_downcase) == "n/a") then empty
				else ({package: {ecosystem: "EUVD", name: $name}, database_specific: {vendor: $vendor, raw_product_version: $product_version}}
							+ (parse_version_ranges($product_version) as $ranges | if ($ranges | length) > 0 then {ranges: $ranges} else {} end)
							+ (parse_exact_versions($product_version) as $versions | if ($versions | length) > 0 then {versions: $versions} else {} end))
				end;

		. as $root
		| ([($root.aliases | split_lines[]), ($root.enisaIdVulnerability[]?.vulnerability.id?)] | dedupe | map(select(. != $root.id))) as $aliases
		| ([$euvd_api_url, ($root.references | split_lines[])] | dedupe) as $reference_urls
		| ([$root.enisaIdProduct[]? | build_affected]) as $affected
		| ({
				schema_version: "1.5.0",
				id: $root.id,
				aliases: $aliases,
				published: $published,
				modified: $modified,
				details: ($root.description // ""),
				references: ($reference_urls | map({type: (. | ref_type), url: .})),
				database_specific: {
					assigner: $root.assigner,
					enisa_uuid: $root.enisaUuid,
					epss: $root.epss
				}
			}
			+ (if (($root.baseScoreVector // "") != "") then {severity: [{type: (if (($root.baseScoreVersion | tostring) | startswith("4")) then "CVSS_V4" else "CVSS_V3" end), score: $root.baseScoreVector}]} else {} end)
			+ (if ($affected | length) > 0 then {affected: $affected} else {} end))
		' "$input_path" > "$output_path"
}

require_command jq
require_command date

output_dir=''
declare -a input_files=()

while [[ $# -gt 0 ]]; do
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		-o|--output-dir)
			if [[ $# -lt 2 ]]; then
				echo 'Missing value for output directory option.' >&2
				exit 1
			fi
			output_dir="$2"
			shift 2
			;;
		-o=*|--output-dir=*)
			output_dir="${1#*=}"
			shift
			;;
		-*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 1
			;;
		*)
			input_files+=("$1")
			shift
			;;
	esac
done

if [[ -z "$output_dir" || ${#input_files[@]} -eq 0 ]]; then
	usage >&2
	exit 1
fi

mkdir -p "$output_dir"

for input_path in "${input_files[@]}"; do
	if ! convert_file "$input_path" "$output_dir/$(basename "$input_path")"; then
		echo "Failed to convert $input_path" >&2
	fi
done