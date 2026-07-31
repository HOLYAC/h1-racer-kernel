package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/HOLYAC/h1-racer-kernel/internal/protocol"
	"github.com/HOLYAC/h1-racer-kernel/internal/race"
	"github.com/HOLYAC/h1-racer-kernel/internal/transport"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("h1-racer-kernel", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "path to RacePlan JSON")
	outputPath := flags.String("output", "", "optional path for RaceReport JSON")
	quiet := flags.Bool("quiet", false, "suppress report JSON on stdout; requires --output")
	validateClientHello := flags.String(
		"validate-client-hello",
		"",
		"validate compact ClientHello hex from a file and exit",
	)
	listProfiles := flags.Bool("list-profiles", false, "list accepted TLS profile names")
	showVersion := flags.Bool("version", false, "print build version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if *listProfiles {
		names := transport.ProfileNames()
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintln(stdout, name)
		}
		return 0
	}
	if *validateClientHello != "" {
		raw, readErr := os.ReadFile(*validateClientHello)
		if readErr != nil {
			fmt.Fprintf(stderr, "read client hello: %v\n", readErr)
			return 2
		}
		if validateErr := transport.ValidateClientHelloHex(string(raw)); validateErr != nil {
			fmt.Fprintf(stderr, "validate client hello: %v\n", validateErr)
			return 2
		}
		fmt.Fprintln(stdout, "valid")
		return 0
	}
	if *planPath == "" {
		fmt.Fprintln(stderr, "--plan is required")
		return 2
	}
	if *quiet && *outputPath == "" {
		fmt.Fprintln(stderr, "--quiet requires --output")
		return 2
	}

	file, err := os.Open(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "open plan: %v\n", err)
		return 2
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var plan protocol.RacePlan
	if err = decoder.Decode(&plan); err != nil {
		fmt.Fprintf(stderr, "decode plan: %v\n", err)
		return 2
	}
	if err = ensureEOF(decoder); err != nil {
		fmt.Fprintf(stderr, "decode plan: %v\n", err)
		return 2
	}
	compiled, err := plan.Compile()
	if err != nil {
		fmt.Fprintf(stderr, "validate plan: %v\n", err)
		return 2
	}

	report := race.Run(context.Background(), compiled)
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encode report: %v\n", err)
		return 2
	}
	encoded = append(encoded, '\n')
	if *outputPath != "" {
		if err = os.WriteFile(*outputPath, encoded, 0o600); err != nil {
			fmt.Fprintf(stderr, "write report: %v\n", err)
			return 2
		}
	}
	if !*quiet {
		if _, err = stdout.Write(encoded); err != nil {
			fmt.Fprintf(stderr, "write stdout: %v\n", err)
			return 2
		}
	}
	if !report.Fired || report.AbortError != "" {
		return 1
	}
	for _, connection := range report.Connections {
		if connection.Error != "" {
			return 1
		}
	}
	return 0
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values in plan")
}
