//go:build linux || darwin

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestRawTerminalStateEnablesRawFlags(t *testing.T) {
	state := &unix.Termios{
		Iflag: unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON,
		Lflag: unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN,
		Cflag: unix.CSIZE | unix.PARENB,
	}

	raw := rawTerminalState(state)

	if raw.Iflag&(unix.IGNBRK|unix.BRKINT|unix.PARMRK|unix.ISTRIP|unix.INLCR|unix.IGNCR|unix.ICRNL|unix.IXON) != 0 {
		t.Fatalf("raw.Iflag = %#x, want raw mode bits cleared", raw.Iflag)
	}
	if raw.Lflag&(unix.ECHO|unix.ECHONL|unix.ICANON|unix.ISIG|unix.IEXTEN) != 0 {
		t.Fatalf("raw.Lflag = %#x, want line mode bits cleared", raw.Lflag)
	}
	if raw.Cflag&unix.PARENB != 0 {
		t.Fatalf("raw.Cflag = %#x, want PARENB cleared", raw.Cflag)
	}
	if raw.Cflag&unix.CSIZE != unix.CS8 {
		t.Fatalf("raw.Cflag = %#x, want character size bits set to CS8", raw.Cflag)
	}
	if raw.Cc[unix.VMIN] != 1 {
		t.Fatalf("raw.Cc[VMIN] = %d, want 1", raw.Cc[unix.VMIN])
	}
	if raw.Cc[unix.VTIME] != 0 {
		t.Fatalf("raw.Cc[VTIME] = %d, want 0", raw.Cc[unix.VTIME])
	}
}
