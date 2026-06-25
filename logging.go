package main

import "log"

var runtimeDebugLoggingEnabled bool

func setRuntimeDebugLogging(enabled bool) {
	runtimeDebugLoggingEnabled = enabled
}

func runtimeDebugLogf(format string, args ...any) {
	if !runtimeDebugLoggingEnabled {
		return
	}

	log.Printf(format, args...)
}

func runtimeDebugLogln(args ...any) {
	if !runtimeDebugLoggingEnabled {
		return
	}

	log.Println(args...)
}
