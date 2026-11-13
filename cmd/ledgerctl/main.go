package main

import (
	"fmt"
	"os"

	"graduation-design/internal/fabric"
)

func main() {
	if err := fabric.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
