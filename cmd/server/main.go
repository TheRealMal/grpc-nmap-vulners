package main

import (
	"grpc-nmap-vulners/pkg/logger"
	"grpc-nmap-vulners/pkg/vulners"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	log := logger.NewLogger(os.Stdout, "[SERVER]", 2)
	logLevel := logger.DEBUG // Specify log level to control logs output

	if err := godotenv.Load(".env"); err != nil {
		if logger.WARNING >= logLevel {
			log.Println("[WARNING] failed to read .env file")
		}
	}
	network, ok := os.LookupEnv("NETWORK")
	if !ok {
		log.Fatal("[CRITICAL] Can't load NETWORK environment variable")
	}
	address, ok := os.LookupEnv("ADDRESS")
	if !ok {
		log.Fatal("[CRITICAL] Can't load ADDRESS environment variable")
	}

	if logger.INFO >= logLevel {
		log.Println("[INFO] starting server...")
	}
	vulners.StartServer(network, address, log, logLevel)
}
