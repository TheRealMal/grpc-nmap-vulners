package main

import (
	"grpc-nmap-vulners/pkg/vulners"
	"log"
	"os"
)

func main() {
	args := os.Args
	if len(args) != 3 {
		log.Fatal("failed to parse arguments")
	}

	response, err := vulners.ScanWithNmap([]string{args[1]}, args[2])
	if err != nil {
		log.Fatalf("failed to scan: %v\n", err)
	}
	log.Printf("%v\n", response)
}
