package logger

import (
	"log"
	"os"
)

// Logger
func NewLogger(outputStream *os.File, prefix string, flag int) *log.Logger {
	return log.New(outputStream, prefix, flag)
}

// Log levels
const (
	DEBUG = iota + 1
	INFO
	WARNING
	ERROR
	CRITICAL
)
