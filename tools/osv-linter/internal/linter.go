package internal

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/tidwall/gjson"

	"github.com/urfave/cli/v2"

	"github.com/ossf/osv-schema/linter/internal/checks"
)

type Content struct {
	filename string
	bytes    []byte
}

func lint(content *Content, checks []*checks.Check) (findings []checks.CheckError) {
	// Parse file into JSON
	if !gjson.ValidBytes(content.bytes) {
		log.Printf("%q: invalid JSON", content.filename)
	}

	record := gjson.ParseBytes(content.bytes)

	for _, check := range checks {
		fmt.Printf("Running %q check on %q\n", check.Name(), content.filename)
		checkFindings := check.Run(&record)
		if checkFindings != nil {
			log.Printf("%q: %q: %#v", content.filename, check.Name(), checkFindings)
		}
		findings = append(findings, checkFindings...)
	}
	return findings
}

func LintCommand(cCtx *cli.Context) error {
	// List check collections.
	if cCtx.String("collection") == "list" {
		fmt.Printf("Available check collections:\n\n")
		for _, collection := range checks.Collections() {
			fmt.Printf("%s: %s\n", collection.Name(), collection.Description())
			for _, check := range collection.Checks() {
				fmt.Printf("\t%s: (%s): %s\n", check.CodeString(), check.Name(), check.Description())
			}
		}
		return nil
	}

	// List all available checks.
	if cCtx.String("check") == "list" {
		fmt.Printf("Available checks:\n\n")
		for _, check := range checks.All() {
			fmt.Printf("%s: (%s): %s\n", check.CodeString(), check.Name(), check.Description())
		}
		return nil
	}

	// Check for things to check.
	if cCtx.NArg() == 0 {
		return errors.New("nothing to check")
	}

	var checksToBeRun []*checks.Check

	// Run the all the checks in a collection.
	if cCtx.String("collection") != "" {
		fmt.Printf("Running %q check collection on %q\n", cCtx.String("collection"), cCtx.Args())
		// Check the requested check collection exists.
		if _, ok := checks.Collections()[cCtx.String("collection")]; !ok {
			return fmt.Errorf("%q is not a valid check collection", cCtx.String("collection"))
		}
		collection := checks.Collections()[cCtx.String("collection")]
		checksToBeRun = collection.Checks()
	}

	// Run just an individual check.
	if cCtx.String("check") != "" {
		// Check the requested check exists.
		if _, ok := checks.All()[cCtx.String("check")]; !ok {
			return fmt.Errorf("%q is not a valid check", cCtx.String("check"))
		}
		checksToBeRun = append(checksToBeRun, checks.All()[cCtx.String("check")])
	}

	perFileFindings := map[string][]checks.CheckError{}

	// Run the check(s) on the files.
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
			// Do the directory thing
		} else {
			// Do the file thing
			recordBytes, err := os.ReadFile(thingToCheck)
			if err != nil {
				log.Printf("%v, skipping", err)
				continue
			}
			findings := lint(&Content{filename: thingToCheck, bytes: recordBytes}, checksToBeRun)
			if findings != nil {
				perFileFindings[thingToCheck] = findings
			}
		}
	}
	if len(perFileFindings) > 0 {
		return errors.New("found errors")
	}
	return nil
}
