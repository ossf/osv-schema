package main

import (
	"log"
	"os"

	"github.com/ossf/osv-schema/linter/internal"
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
							&cli.StringFlag{
								Name:  "collection",
								Value: "ALL",
								Usage: "check collection to use (use 'list' to see)",
							},
							&cli.StringSliceFlag{
								Name:  "check",
								Value: &cli.StringSlice{},
								Usage: "explicitly run a specific check (use 'list' to see)",
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
