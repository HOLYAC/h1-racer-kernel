package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/HOLYAC/h1-racer-kernel/internal/artifact"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "archive":
		return runArchive(args[1:], stdout, stderr)
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func runArchive(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("archive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "directory tree to archive")
	output := flags.String("output", "", "output ZIP or JAR path")
	prefix := flags.String("prefix", "", "optional fixed archive path prefix")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *source == "" || *output == "" {
		fmt.Fprintln(stderr, "archive requires --source and --output")
		return 2
	}
	if err := artifact.WriteDeterministicZip(*source, *output, *prefix); err != nil {
		fmt.Fprintf(stderr, "archive: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, *output)
	return 0
}

func runKeygen(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	privatePath := flags.String("private", "", "new PKCS#8 Ed25519 private PEM path")
	publicPath := flags.String("public", "", "new PKIX Ed25519 public PEM path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *privatePath == "" || *publicPath == "" {
		fmt.Fprintln(stderr, "keygen requires --private and --public")
		return 2
	}
	if err := artifact.GenerateKeyPair(*privatePath, *publicPath); err != nil {
		fmt.Fprintf(stderr, "keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "private=%s\npublic=%s\n", *privatePath, *publicPath)
	return 0
}

func runSign(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	subject := flags.String("subject", "", "release artifact to sign")
	privatePath := flags.String("private", "", "PKCS#8 Ed25519 private PEM path")
	output := flags.String("output", "", "signature JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || *privatePath == "" || *output == "" {
		fmt.Fprintln(stderr, "sign requires --subject, --private, and --output")
		return 2
	}
	if err := artifact.SignFile(*subject, *privatePath, *output); err != nil {
		fmt.Fprintf(stderr, "sign: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, *output)
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	subject := flags.String("subject", "", "release artifact to verify")
	publicPath := flags.String("public", "", "PKIX Ed25519 public PEM path")
	signature := flags.String("signature", "", "signature JSON path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || *publicPath == "" || *signature == "" {
		fmt.Fprintln(stderr, "verify requires --subject, --public, and --signature")
		return 2
	}
	if err := artifact.VerifyFile(*subject, *publicPath, *signature); err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "verified")
	return 0
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: h1-racer-artifact <archive|keygen|sign|verify> [flags]")
}
