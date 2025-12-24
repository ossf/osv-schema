package main

import (
	"log"
	"os"

	"github.com/ossf/osv-schema/linter/internal"
	"github.com/ossf/osv-schema/linter/internal/checks"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "osv",
		Usage: "OSV general purpose tool",
		Commands: []*cli.Command{
			{
				Name:  "record",
				Usage: "operations on OSV records",
				Subcommands: []*cli.Command{
					{
						Name: "lint",
						Flags: []cli.Flag{
							&cli.BoolFlag{
								Name:  "verbose",
								Usage: "verbose output",
							},
							&cli.StringFlag{
								Name:  "collection",
								Value: "ALL",
								Usage: "check collection to use (use 'list' to see)",
							},
							&cli.StringSliceFlag{
								Name:  "checks",
								Value: &cli.StringSlice{},
								Usage: "explicitly run a specific check (use 'list' to see)",
							},
							&cli.StringSliceFlag{
								Name:  "ecosystems",
								Value: &cli.StringSlice{},
								Usage: "the ecosystems to constrain package checks to (use 'list' to see)",
							},
							&cli.BoolFlag{
								Name:  "json",
								Usage: "output results as JSON",
							},
							&cli.BoolFlag{
								Name:  "new-ecosystem",
								Usage: "ignore certain checks for new ecosystems (e.g. schema pattern checks, unsupported ecosystem checks)",
							},
							&cli.IntFlag{
								Name:  "parallel",
								Usage: "how many files to process in parallel",
								Value: 1,
							},
							&cli.StringFlag{
								Name:  "schema-file",
								Usage: "path to a custom schema file to be used instead of the embedded one",
								Action: func(_ *cli.Context, s string) error {
									b, err := os.ReadFile(s)

									if err == nil {
										checks.LoadedSchema = b
									}

									return err
								},
							},
						},
						Aliases: []string{"check"},
						Usage:   "check OSV records for correctness",
						Action:  internal.LintCommand,
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
