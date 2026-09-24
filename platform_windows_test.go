//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestRawConsoleModeEnablesRawFlags(t *testing.T) {
	mode := uint32(windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT)

	raw := rawConsoleMode(mode)

	if raw&(windows.ENABLE_ECHO_INPUT|windows.ENABLE_LINE_INPUT|windows.ENABLE_PROCESSED_INPUT) != 0 {
		t.Fatalf("raw = %#x, want cooked console flags cleared", raw)
	}
	if raw&windows.ENABLE_VIRTUAL_TERMINAL_INPUT == 0 {
		t.Fatalf("raw = %#x, want ENABLE_VIRTUAL_TERMINAL_INPUT set", raw)
	}
}
