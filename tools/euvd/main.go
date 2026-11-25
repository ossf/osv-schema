package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "dump":
		return runDump(args[1:], stdout, stderr, httpClient, apiSearchURL)
	case "convert":
		return runConvert(args[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `EUVD tools

Usage:
	go run . dump [options] out_dir
	go run . convert -o OUTPUT_DIR input_files...

Commands:
	dump     Download EUVD advisories as JSON files
	convert  Convert EUVD JSON files to OSV JSON`)
}
