package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const apiSearchURL = "https://euvdservices.enisa.europa.eu/api/search"
const maxRequestAttempts = 5
const pageInterval = 250 * time.Millisecond

var httpClient = &http.Client{Timeout: 60 * time.Second}

type dumpResponse struct {
	Items []map[string]any `json:"items"`
	Total *int             `json:"total"`
}

func runDump(args []string, stdout, stderr io.Writer, client *http.Client, baseURL string) error {
	flags := flag.NewFlagSet("dump", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {
		fmt.Fprintln(stderr, `Usage: euvd dump [options] out_dir

Server-side filters:
	--fromDate DATE --toDate DATE --fromScore VALUE --toScore VALUE
	--fromEpss VALUE (--epss is an alias) --toEpss VALUE --exploited BOOL

Field filters:
	--id ID --description TEXT --datePublished TEXT --dateUpdated TEXT
	--baseScore VALUE --baseScoreVersion VERSION --baseScoreVector VECTOR
	--aliases TEXT --assigner NAME --exploitedSince DATE
	--product NAME --vendor NAME --references TEXT`)
	}

	var help bool
	flags.BoolVar(&help, "h", false, "show help")
	flags.BoolVar(&help, "help", false, "show help")
	values := map[string]*string{
		"fromDate":         new(string),
		"toDate":           new(string),
		"fromScore":        new(string),
		"toScore":          new(string),
		"fromEpss":         new(string),
		"toEpss":           new(string),
		"exploited":        new(string),
		"id":               new(string),
		"description":      new(string),
		"datePublished":    new(string),
		"dateUpdated":      new(string),
		"baseScore":        new(string),
		"baseScoreVersion": new(string),
		"baseScoreVector":  new(string),
		"aliases":          new(string),
		"assigner":         new(string),
		"exploitedSince":   new(string),
		"product":          new(string),
		"vendor":           new(string),
		"references":       new(string),
	}
	for name, value := range values {
		flags.StringVar(value, name, "", "")
	}
	flags.StringVar(values["fromEpss"], "epss", "", "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.Usage()
			return nil
		}
		return fmt.Errorf("parse dump options: %w", err)
	}
	if help {
		flags.Usage()
		return nil
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return errors.New("dump requires exactly one output directory")
	}

	apiNames := map[string]string{
		"fromDate": "fromDate", "toDate": "toDate", "fromScore": "fromScore",
		"toScore": "toScore", "fromEpss": "fromEpss", "toEpss": "toEpss",
		"exploited": "exploited", "description": "text", "assigner": "assigner",
		"product": "product", "vendor": "vendor",
	}
	localNames := map[string]string{
		"id": "id", "description": "description", "datePublished": "datePublished",
		"dateUpdated": "dateUpdated", "baseScore": "baseScore",
		"baseScoreVersion": "baseScoreVersion", "baseScoreVector": "baseScoreVector",
		"aliases": "aliases", "assigner": "assigner", "exploitedSince": "exploitedSince",
		"product": "enisaIdProduct", "vendor": "enisaIdVendor", "references": "references",
	}
	apiParams := url.Values{}
	filters := make(map[string]string)
	for name, value := range values {
		if *value == "" {
			continue
		}
		if parameter, ok := apiNames[name]; ok {
			apiParams.Set(parameter, *value)
		}
		if field, ok := localNames[name]; ok {
			filters[field] = *value
		}
	}
	if *values["fromEpss"] == "" {
		if value := flags.Lookup("epss").Value.String(); value != "" {
			apiParams.Set("fromEpss", value)
		}
	}

	return dumpAdvisories(client, baseURL, flags.Arg(0), apiParams, filters, stdout)
}

func dumpAdvisories(client *http.Client, baseURL, outputDirectory string, apiParams url.Values, filters map[string]string, stdout io.Writer) error {
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	page, fetched, dumped := 0, 0, 0
	var total *int
	for {
		if page > 0 {
			time.Sleep(pageInterval)
		}
		params := make(url.Values, len(apiParams)+1)
		for key, values := range apiParams {
			params[key] = append([]string(nil), values...)
		}
		params.Set("page", strconv.Itoa(page))
		requestURL := baseURL + "?" + params.Encode()
		request, err := http.NewRequest(http.MethodGet, requestURL, nil)
		if err != nil {
			return fmt.Errorf("build EUVD request: %w", err)
		}
		body, err := fetchDumpPage(client, request, page, time.Sleep)
		if err != nil {
			return err
		}
		if len(body.Items) == 0 {
			break
		}
		if total == nil {
			total = body.Total
		}
		fetched += len(body.Items)

		for _, item := range body.Items {
			if !matchesFilters(item, filters) {
				continue
			}
			id, ok := item["id"].(string)
			if !ok || id == "" || filepath.Base(id) != id || id == "." || id == ".." {
				return fmt.Errorf("EUVD response contains an invalid advisory id: %v", item["id"])
			}
			path := filepath.Join(outputDirectory, id+".json")
			file, err := os.Create(path)
			if err != nil {
				return fmt.Errorf("create %s: %w", path, err)
			}
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			encoder.SetEscapeHTML(false)
			encodeErr := encoder.Encode(item)
			closeErr := file.Close()
			if encodeErr != nil {
				return fmt.Errorf("write %s: %w", path, encodeErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close %s: %w", path, closeErr)
			}
			dumped++
			if dumped%500 == 0 {
				fmt.Fprintf(stdout, "Up to %d advisories.\n", dumped)
			}
		}

		page++
		if total != nil && fetched >= *total {
			break
		}
	}
	fmt.Fprintf(stdout, "Dumped %d advisories.\n", dumped)
	return nil
}

func fetchDumpPage(client *http.Client, request *http.Request, page int, wait func(time.Duration)) (dumpResponse, error) {
	for attempt := 1; attempt <= maxRequestAttempts; attempt++ {
		response, err := client.Do(request)
		if err != nil {
			if attempt == maxRequestAttempts {
				return dumpResponse{}, fmt.Errorf("request EUVD page %d after %d attempts: %w", page, attempt, err)
			}
			wait(time.Duration(1<<uint(attempt-1)) * time.Second)
			continue
		}

		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
			var body dumpResponse
			err = json.NewDecoder(response.Body).Decode(&body)
			response.Body.Close()
			if err != nil {
				return dumpResponse{}, fmt.Errorf("decode EUVD page %d: %w", page, err)
			}
			return body, nil
		}

		responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		response.Body.Close()
		if !isRetryableStatus(response.StatusCode) || attempt == maxRequestAttempts {
			message := strings.TrimSpace(string(responseBody))
			if message != "" {
				return dumpResponse{}, fmt.Errorf("request EUVD page %d after %d attempts: HTTP %s: %s", page, attempt, response.Status, message)
			}
			return dumpResponse{}, fmt.Errorf("request EUVD page %d after %d attempts: HTTP %s", page, attempt, response.Status)
		}

		delay := time.Duration(1<<uint(attempt-1)) * time.Second
		if retryAfter := parseRetryAfter(response.Header.Get("Retry-After")); retryAfter > delay {
			delay = retryAfter
		}
		wait(delay)
	}
	return dumpResponse{}, fmt.Errorf("request EUVD page %d failed after retries", page)
}

func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func parseRetryAfter(value string) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if retryTime, err := http.ParseTime(value); err == nil {
		if delay := time.Until(retryTime); delay > 0 {
			return delay
		}
	}
	return 0
}

func matchesFilters(item map[string]any, filters map[string]string) bool {
	for field, expected := range filters {
		value, exists := item[field]
		if !exists {
			return false
		}
		if field == "baseScore" {
			if fmt.Sprint(value) != expected {
				return false
			}
			continue
		}
		var searchable string
		if text, ok := value.(string); ok {
			searchable = text
		} else {
			encoded, err := json.Marshal(value)
			if err != nil {
				return false
			}
			searchable = string(encoded)
		}
		if !strings.Contains(strings.ToLower(searchable), strings.ToLower(expected)) {
			return false
		}
	}
	return true
}
