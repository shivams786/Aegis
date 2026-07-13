package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
)

func main() {
	gateway := flag.String("gateway", "http://localhost:8080", "Aegis gateway base URL")
	flag.Parse()

	if _, err := url.ParseRequestURI(*gateway); err != nil {
		fmt.Fprintf(os.Stderr, "invalid gateway URL: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("demo agent configured for %s\n", *gateway)
	fmt.Println("full MCP invocation scenarios are introduced after the secure invocation pipeline lands")
}
