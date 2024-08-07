package internal

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/tidwall/gjson"

	"github.com/urfave/cli/v2"

	"github.com/ossf/osv-schema/linter/internal/checks"
)

type Content struct {
	filename string
	bytes    []byte
}

func lint(content *Content, checks []*checks.CheckDef) (findings []checks.CheckError) {
	// Parse file into JSON
	if !gjson.ValidBytes(content.bytes) {
		log.Printf("%q: invalid JSON", content.filename)
	}

	record := gjson.ParseBytes(content.bytes)

	for _, check := range checks {
		fmt.Printf("Running %q check on %q\n", check.Name, content.filename)
		checkFindings := check.Run(&record)
		if checkFindings != nil {
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
	if cCtx.String("check") == "list" {
		fmt.Printf("Available checks:\n\n")
		for _, check := range checks.CollectionFromName("ALL").Checks {
			fmt.Printf("%s: (%s): %s\n", check.Code, check.Name, check.Description)
		}
		return nil
	}

	// Check for things to check.
	if cCtx.NArg() == 0 {
		return errors.New("nothing to check")
	}

	var checksToBeRun []*checks.CheckDef

	// Run all the checks in a collection.
	if cCtx.String("collection") != "" {
		fmt.Printf("Running %q check collection on %q\n", cCtx.String("collection"), cCtx.Args())
		// Check the requested check collection exists.
		collection := checks.CollectionFromName(cCtx.String("collection"))
		if collection == nil {
			return fmt.Errorf("%q is not a valid check collection", cCtx.String("collection"))
		}
		checksToBeRun = collection.Checks
	}

	// Run just an individual check, overriding anything discovered from a collection.
	if code := cCtx.String("check"); code != "" {
		// Check the requested check exists.
		check := checks.FromCode(code)
		if check == nil {
			return fmt.Errorf("%q is not a valid check", code)
		}
		checksToBeRun = []*checks.CheckDef{check}
	}

	perFileFindings := map[string][]checks.CheckError{}

	// Figure out what files to check.
	var filesToCheck []string
	for _, thingToCheck := range cCtx.Args().Slice() {
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
			log.Printf("Found %d files in %q", len(filesToCheck), thingToCheck)
		} else {
			filesToCheck = append(filesToCheck, thingToCheck)
		}
	}

	// Run the check(s) on the files.
	for _, fileToCheck := range filesToCheck {
		recordBytes, err := os.ReadFile(fileToCheck)
		if err != nil {
			log.Printf("%v, skipping", err)
			continue
		}
		findings := lint(&Content{filename: fileToCheck, bytes: recordBytes}, checksToBeRun)
		if findings != nil {
			perFileFindings[fileToCheck] = findings
		}
	}

	if len(perFileFindings) > 0 {
		return errors.New("found errors")
	}
	return nil
}
