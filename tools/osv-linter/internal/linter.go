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

func LintCommand(cCtx *cli.Context) error {
	if cCtx.String("collection") == "list" {
		fmt.Printf("Available check collections:\n\n")
		for _, collection := range checks.CheckCollections() {
			fmt.Printf("%s: %s\n", collection.Name(), collection.Description())
			for _, check := range collection.Checks() {
				fmt.Printf("\t%s: (%s): %s\n", check.CodeString(), check.Name(), check.Description())
			}
		}
		return nil
	}

	if cCtx.String("check") == "list" {
		fmt.Printf("Available checks:\n\n")
		for _, check := range checks.Checks() {
			fmt.Printf("%s: (%s): %s\n", check.CodeString(), check.Name(), check.Description())
		}
		return nil
	}

	if cCtx.NArg() == 0 {
		return errors.New("nothing to check")
	}

	for _, fileToCheck := range cCtx.Args().Slice() {

		// Check file exists.
		recordBytes, err := os.ReadFile(fileToCheck)
		if err != nil {
			log.Printf("%v, skipping", err)
			continue
		}

		// Parse file into JSON
		if !gjson.ValidBytes(recordBytes) {
			log.Printf("%q: invalid JSON", fileToCheck)
		}

		record := gjson.ParseBytes(recordBytes)

		if cCtx.String("check") != "" {
			fmt.Printf("Running %q check on %q\n", cCtx.String("check"), fileToCheck)
			// Check the requested check exists.
			if _, ok := checks.Checks()[cCtx.String("check")]; !ok {
				return fmt.Errorf("%q is not a valid check", cCtx.String("check"))
			}
			// Run just the requested check.
			check := checks.Checks()[cCtx.String("check")]
			// TODO: store in a per-file map so a per-file summary can be produced.
			result := check.Run(&record)
			if result != nil {
				log.Printf("%q: %q: %#v", fileToCheck, cCtx.String("check"), result)
			}
			continue
		}

		if cCtx.String("collection") != "" {
			fmt.Printf("Running %q check collection on %q\n", cCtx.String("collection"), cCtx.Args())
			// Check the requested check collection exists.
			if _, ok := checks.CheckCollections()[cCtx.String("collection")]; !ok {
				return fmt.Errorf("%q is not a valid check collection", cCtx.String("collection"))
			}
			// Run all checks in collection
			collection := checks.CheckCollections()[cCtx.String("collection")]
			for _, check := range collection.Checks() {
				// TODO: store in a per-file per-check map so a per-file summary can be produced.
				result := check.Run(&record)
				if result != nil {
					log.Printf("%q: %q: %#v", fileToCheck, check.Name(), result)
				}
			}
			continue
		}
	}
	return nil
}
