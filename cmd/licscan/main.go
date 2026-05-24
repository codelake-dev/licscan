// Command licscan is the open-source license & compliance scanner CLI.
//
// See `licscan --help` or https://github.com/codelake-ai/licscan for usage.
package main

import (
	"os"

	"github.com/codelake-ai/licscan/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
