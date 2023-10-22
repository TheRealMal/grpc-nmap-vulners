package main

import (
	"grpc-nmap-vulners/pkg/vulners"
)

func main() {
	vulners.StartServer("tcp", "127.0.0.1:8080")
}
