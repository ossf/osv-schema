package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"

	"github.com/tidwall/gjson"

	"golang.org/x/sync/errgroup"
	"golang.org/x/term"

	"github.com/urfave/cli/v2"

	"github.com/ossf/osv-schema/linter/internal/checks"
	"github.com/ossf/osv-schema/linter/internal/pkgchecker"
)

type Content struct {
	filename string
	bytes    []byte
}

// Config defines the arguments for lint().
type Config struct {
	checks       []*checks.CheckDef // which checks to run.
	ecosystems   []string           // which ecosystems to limit package checks to.
	verbose      bool               // whether to emit verbose output.
	json         bool               // whether to output results as JSON.
	newEcosystem bool               // whether to ignore certain checks for new ecosystems.
}

func lint(content *Content, config *Config) (findings []checks.CheckError) {
	// Parse file into JSON
	if !gjson.ValidBytes(content.bytes) {
		log.Printf("%q: invalid JSON", content.filename)
	}

	record := gjson.ParseBytes(content.bytes)

	for _, check := range config.checks {
		if config.verbose && !config.json {
			fmt.Printf("Running %q check on %q\n", check.Name, content.filename)
		}
		checkConfig := checks.Config{Verbose: config.verbose, Ecosystems: config.ecosystems, NewEcosystem: config.newEcosystem}
		checkFindings := check.Run(&record, &checkConfig)
		if checkFindings != nil && config.verbose {
			log.Printf("%q: %q: %#v", content.filename, check.Name, checkFindings)
		}
		findings = append(findings, checkFindings...)
	}
	return findings
}

func LintCommand(cCtx *cli.Context) error {
	// List check collections.
	if cCtx.String("collection") == "list" {
		fmt.Printf("Available check collections:\n\n")
		for _, collection := range checks.Collections {
			fmt.Printf("%s: %s\n", collection.Name, collection.Description)
			for _, check := range collection.Checks {
				fmt.Printf("\t%s: (%s): %s\n", check.Code, check.Name, check.Description)
			}
		}
		return nil
	}

	// List all available checks.
	if slices.Contains(cCtx.StringSlice("checks"), "list") {
		fmt.Printf("Available checks:\n\n")
		for _, check := range checks.CollectionFromName("ALL").Checks {
			fmt.Printf("%s: (%s): %s\n", check.Code, check.Name, check.Description)
		}
		return nil
	}

	// List all supported ecosystems.
	if slices.Contains(cCtx.StringSlice("ecosystems"), "list") {
		fmt.Printf("Supported ecosystems:\n\n")
		for _, ecosystem := range pkgchecker.SupportedEcosystems {
			fmt.Printf("%s\n", ecosystem)
		}
		return nil
	}

	// Check for things to check.
	if !cCtx.Args().Present() && term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("no files to check (use - for stdin)")
	}

	var checksToBeRun []*checks.CheckDef

	// Run just individual checks.
	for _, checkRequested := range cCtx.StringSlice("checks") {
		// Check the requested check exists.
		check := checks.FromCode(checkRequested)
		if check == nil {
			return fmt.Errorf("%q is not a valid check (use \"list\" to see all available checks)", checkRequested)
		}
		checksToBeRun = append(checksToBeRun, check)
	}

	// Run all the checks in a collection, if no specific checks requested.
	if checksToBeRun == nil && cCtx.String("collection") != "" {
		if cCtx.Bool("verbose") && !cCtx.Bool("json") { // Don't print this to stdout if JSON output is enabled
			if cCtx.Args().Present() {
				fmt.Printf("Running %q check collection on %q\n", cCtx.String("collection"), cCtx.Args().Slice())
			} else {
				fmt.Printf("Running %q check collection on <stdin>\n", cCtx.String("collection"))
			}
		}
		// Check the requested check collection exists.
		collection := checks.CollectionFromName(cCtx.String("collection"))
		if collection == nil {
			return fmt.Errorf("%q is not a valid check collection", cCtx.String("collection"))
		}
		checksToBeRun = collection.Checks
	}

	// Figure out what files to check.
	var filesToCheck []string
	for _, thingToCheck := range cCtx.Args().Slice() {
		// Special case "-" for stdin.
		if thingToCheck == "-" {
			filesToCheck = append(filesToCheck, "<stdin>")
			continue
		}

		file, err := os.Open(thingToCheck)
		if err != nil {
			log.Printf("%v, skipping", err)
			continue
		}
		defer file.Close()

		fileInfo, err := file.Stat()
		if err != nil {
			log.Printf("%v, skipping", err)
			continue
		}

		if fileInfo.IsDir() {
			err := filepath.WalkDir(thingToCheck, func(f string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() && filepath.Ext(d.Name()) == ".json" {
					filesToCheck = append(filesToCheck, f)
				}
				return nil
			})
			if err != nil {
				log.Printf("%v, skipping", err)
				continue
			}
			if cCtx.Bool("verbose") {
				log.Printf("Found %d files in %q", len(filesToCheck), thingToCheck)
			}
		} else {
			filesToCheck = append(filesToCheck, thingToCheck)
		}
	}

	// Default to stdin if no files were specified.
	if len(filesToCheck) == 0 {
		filesToCheck = append(filesToCheck, "<stdin>")
	}

	perFileFindings := checkFiles(cCtx, filesToCheck, checksToBeRun)

	if cCtx.Bool("json") {
		outputMap := perFileFindings
		if outputMap == nil {
			outputMap = make(map[string][]checks.CheckError) // Ensure a non-nil map for JSON, results in {}
		}
		jsonData, err := json.MarshalIndent(outputMap, "", "  ")
		if err != nil {
			log.Printf("Error marshalling findings to JSON: %v", err)
			return fmt.Errorf("internal error: could not format results as JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		for filename, findings := range perFileFindings {
			fmt.Printf("%s:\n", filename)
			for _, finding := range findings {
				fmt.Printf("\t * %s\n", finding.Error())
			}
		}
	}

	if len(perFileFindings) > 0 {
		return errors.New("found errors")
	}
	return nil
}

func checkFile(cCtx *cli.Context, fileToCheck string, checksToBeRun []*checks.CheckDef) ([]checks.CheckError, error) {
	var recordBytes []byte
	var err error
	// Special case for stdin.
	if fileToCheck == "<stdin>" {
		recordBytes, err = io.ReadAll(os.Stdin)
	} else {
		recordBytes, err = os.ReadFile(fileToCheck)
	}
	if err != nil {
		return nil, err
	}
	return lint(&Content{filename: fileToCheck, bytes: recordBytes}, &Config{
		verbose:      cCtx.Bool("verbose"),
		checks:       checksToBeRun,
		ecosystems:   cCtx.StringSlice("ecosystems"),
		json:         cCtx.Bool("json"), // Pass the JSON output mode
		newEcosystem: cCtx.Bool("new-ecosystem"),
	}), nil
}

func checkFiles(cCtx *cli.Context, filesToCheck []string, checksToBeRun []*checks.CheckDef) map[string][]checks.CheckError {
	perFileFindings := map[string][]checks.CheckError{}

	conLimit := cCtx.Int("parallel")

	if len(filesToCheck) == 0 {
		return perFileFindings
	}

	var eg errgroup.Group

	eg.SetLimit(conLimit)

	for _, fileToCheck := range filesToCheck {
		eg.Go(func() error {
			findings, err := checkFile(cCtx, fileToCheck, checksToBeRun)

			if err != nil {
				log.Printf("%v, skipping", err)
			} else if findings != nil {
				perFileFindings[fileToCheck] = findings
			}

			return nil
		})
	}

	// errors are handled within the go routines
	_ = eg.Wait()

	return perFileFindings
}
