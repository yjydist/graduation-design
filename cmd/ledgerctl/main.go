package main

import (
	"fmt"
	"os"

	"graduation-design/internal/ledger"
)

func main() {
	if err := ledger.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
