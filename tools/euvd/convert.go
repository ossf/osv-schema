package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const euvdAPIURLPrefix = "https://euvdservices.enisa.europa.eu/api/enisaid?id="

var (
	whitespaceOrComma = regexp.MustCompile(`[\s,]`)
	versionOperator   = regexp.MustCompile(`^(<=|>=|=|<|>)\s*(.+)$`)
)

func runConvert(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("convert", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: euvd convert -o OUTPUT_DIR input_files...")
		fmt.Fprintln(stderr, "Options: -h, --help, -o OUTPUT_DIR, --output-dir OUTPUT_DIR")
	}
	var help bool
	var outputDirectory string
	flags.BoolVar(&help, "h", false, "show help")
	flags.BoolVar(&help, "help", false, "show help")
	flags.StringVar(&outputDirectory, "o", "", "output directory")
	flags.StringVar(&outputDirectory, "output-dir", "", "output directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.Usage()
			return nil
		}
		return fmt.Errorf("parse convert options: %w", err)
	}
	if help {
		flags.Usage()
		return nil
	}
	if outputDirectory == "" || flags.NArg() == 0 {
		flags.Usage()
		return errors.New("convert requires an output directory and input files")
	}
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	var failures []string
	for _, inputPath := range flags.Args() {
		outputPath := filepath.Join(outputDirectory, filepath.Base(inputPath))
		if err := convertFile(inputPath, outputPath); err != nil {
			fmt.Fprintf(stderr, "Failed to convert %s: %v\n", inputPath, err)
			failures = append(failures, inputPath)
			continue
		}
		fmt.Fprintf(stdout, "Converted %s\n", inputPath)
	}
	if len(failures) > 0 {
		return fmt.Errorf("failed to convert %d input file(s)", len(failures))
	}
	return nil
}

func convertFile(inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	var input map[string]any
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	converted := convertRecord(input)
	output, err := json.MarshalIndent(converted, "", "  ")
	if err != nil {
		return fmt.Errorf("encode OSV JSON: %w", err)
	}
	output = append(output, '\n')
	if err := os.WriteFile(outputPath, output, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func convertRecord(root map[string]any) map[string]any {
	id := stringValue(root["id"])
	aliases := make([]any, 0)
	for _, alias := range splitLines(stringValue(root["aliases"])) {
		aliases = appendUnique(aliases, alias)
	}
	for _, vulnerability := range arrayValue(root["enisaIdVulnerability"]) {
		vulnerabilityObject := mapValue(vulnerability)
		details := mapValue(vulnerabilityObject["vulnerability"])
		if alias, ok := details["id"].(string); ok {
			aliases = appendUnique(aliases, alias)
		}
	}
	filteredAliases := make([]any, 0, len(aliases))
	for _, alias := range aliases {
		if alias != id {
			filteredAliases = append(filteredAliases, alias)
		}
	}

	apiURL := euvdAPIURLPrefix + id
	references := make([]any, 0)
	for _, reference := range append([]string{apiURL}, splitLines(stringValue(root["references"]))...) {
		references = appendUnique(references, reference)
	}
	formattedReferences := make([]any, 0, len(references))
	for _, reference := range references {
		url := reference.(string)
		formattedReferences = append(formattedReferences, map[string]any{"type": referenceType(url), "url": url})
	}

	affected := make([]any, 0)
	for _, product := range arrayValue(root["enisaIdProduct"]) {
		if entry, ok := buildAffected(mapValue(product)); ok {
			affected = append(affected, entry)
		}
	}

	databaseSpecific := map[string]any{
		"assigner":           root["assigner"],
		"enisa_uuid":         root["enisaUuid"],
		"epss":               root["epss"],
		"base_score":         root["baseScore"],
		"base_score_version": root["baseScoreVersion"],
		"exploited_since":    root["exploitedSince"],
		"enisa_vendors":      vendorNames(root["enisaIdVendor"]),
	}

	output := map[string]any{
		"schema_version":    "1.5.0",
		"id":                root["id"],
		"aliases":           filteredAliases,
		"published":         convertDate(stringValue(root["datePublished"])),
		"modified":          convertDate(stringValue(root["dateUpdated"])),
		"details":           valueOr(root["description"], ""),
		"references":        formattedReferences,
		"database_specific": databaseSpecific,
	}
	if vector := stringValue(root["baseScoreVector"]); vector != "" {
		severityType := "CVSS_V3"
		if strings.HasPrefix(stringValue(root["baseScoreVersion"]), "4") {
			severityType = "CVSS_V4"
		}
		output["severity"] = []any{map[string]any{"type": severityType, "score": vector}}
	}
	if len(affected) > 0 {
		output["affected"] = affected
	}
	return output
}

func buildAffected(productEntry map[string]any) (map[string]any, bool) {
	product := mapValue(productEntry["product"])
	name := stringValue(product["name"])
	if name == "" || strings.EqualFold(name, "n/a") {
		return nil, false
	}
	vendor := mapValue(product["vendor"])["name"]
	productVersion := strings.TrimSpace(stringValue(productEntry["product_version"]))

	entry := map[string]any{
		"package": map[string]any{"ecosystem": "EUVD", "name": name},
		"database_specific": map[string]any{
			"vendor": vendor, "raw_product_version": productVersion,
		},
	}
	if ranges := parseVersionRanges(productVersion); len(ranges) > 0 {
		entry["ranges"] = ranges
	}
	if versions := parseExactVersions(productVersion); len(versions) > 0 {
		entry["versions"] = versions
	}
	return entry, true
}

func parseExactVersions(version string) []string {
	if version == "" || strings.EqualFold(version, "n/a") || strings.EqualFold(version, "unknown") || whitespaceOrComma.MatchString(version) {
		return nil
	}
	return []string{version}
}

func parseVersionRanges(version string) []map[string]any {
	normalized := strings.TrimSpace(version)
	if normalized == "" || strings.EqualFold(normalized, "n/a") || strings.EqualFold(normalized, "unknown") {
		return nil
	}
	lowered := strings.ToLower(normalized)
	if strings.HasPrefix(lowered, "before and including ") {
		end := strings.TrimSpace(normalized[len("before and including "):])
		return []map[string]any{{"type": "ECOSYSTEM", "events": []any{map[string]string{"introduced": "0"}, map[string]string{"last_affected": end}}}}
	}
	if strings.HasPrefix(lowered, "before ") {
		end := strings.TrimSpace(normalized[len("before "):])
		return []map[string]any{{"type": "ECOSYSTEM", "events": []any{map[string]string{"introduced": "0"}, map[string]string{"fixed": end}}}}
	}

	parts := strings.Split(normalized, ",")
	type spec struct {
		operator string
		version  string
	}
	specs := make([]spec, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		match := versionOperator.FindStringSubmatch(part)
		if match == nil {
			return nil
		}
		specs = append(specs, spec{operator: match[1], version: strings.TrimSpace(match[2])})
	}
	if len(specs) == 0 || (len(specs) == 1 && specs[0].operator == "=") {
		return nil
	}

	events := make([]any, 0, len(specs)+1)
	hasLower := false
	hasUpper := false
	for _, item := range specs {
		switch item.operator {
		case ">=", ">":
			events = append(events, map[string]string{"introduced": item.version})
			hasLower = true
		case "<":
			events = append(events, map[string]string{"fixed": item.version})
			hasUpper = true
		case "<=":
			events = append(events, map[string]string{"last_affected": item.version})
			hasUpper = true
		}
	}
	if len(events) == 0 {
		return nil
	}
	if !hasLower && hasUpper {
		events = append([]any{map[string]string{"introduced": "0"}}, events...)
	}
	return []map[string]any{{"type": "ECOSYSTEM", "events": events}}
}

func referenceType(reference string) string {
	if strings.Contains(reference, "nvd.nist.gov/vuln/detail/") ||
		strings.Contains(reference, "github.com/advisories/") ||
		strings.Contains(reference, "/security/advisories/") ||
		strings.Contains(reference, "euvd.enisa.europa.eu/") ||
		strings.Contains(reference, "euvdservices.enisa.europa.eu/api/enisaid") {
		return "ADVISORY"
	}
	if strings.Contains(reference, "/commit/") || strings.Contains(reference, "/pull/") || strings.Contains(reference, "/compare/") {
		return "FIX"
	}
	return "WEB"
}

func convertDate(value string) string {
	if value == "" {
		return value
	}
	normalized := strings.ReplaceAll(value, ", ", " ")
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"Jan 2 2006 3:04:05 PM",
		"Jan 2 2006 3:04 PM",
		"January 2 2006 3:04:05 PM",
		"January 2 2006 3:04 PM",
	}
	for _, layout := range layouts {
		if parsed, err := time.ParseInLocation(layout, normalized, time.UTC); err == nil {
			return parsed.UTC().Format("2006-01-02T15:04:05Z")
		}
	}
	return value
}

func splitLines(value string) []string {
	if value == "" {
		return nil
	}
	lines := strings.Split(value, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func appendUnique(items []any, value any) []any {
	for _, existing := range items {
		if existing == value {
			return items
		}
	}
	return append(items, value)
}

func vendorNames(value any) []any {
	names := make([]any, 0)
	for _, vendor := range arrayValue(value) {
		name, ok := mapValue(mapValue(vendor)["vendor"])["name"]
		if !ok {
			name = nil
		}
		names = append(names, name)
	}
	return names
}

func arrayValue(value any) []any {
	items, _ := value.([]any)
	return items
}

func mapValue(value any) map[string]any {
	object, _ := value.(map[string]any)
	if object == nil {
		return map[string]any{}
	}
	return object
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func valueOr(value, fallback any) any {
	if value == nil {
		return fallback
	}
	return value
}
