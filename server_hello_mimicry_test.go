package tls

import (
	"testing"
	"time"
)

func TestServerHelloMimicryDelayInvalidRange(t *testing.T) {
	c := &Config{
		ServerHelloMimicryMinimumDelay: 10 * time.Millisecond,
		ServerHelloMimicryMaximumDelay: 5 * time.Millisecond,
	}

	if _, err := c.serverHelloMimicryDelay(); err == nil {
		t.Fatal("expected error for invalid ServerHello mimicry delay range")
	}
}

func TestServerHelloMimicryDelayRange(t *testing.T) {
	c := &Config{
		ServerHelloMimicryMinimumDelay: 2 * time.Millisecond,
		ServerHelloMimicryMaximumDelay: 4 * time.Millisecond,
	}

	for range 10 {
		delay, err := c.serverHelloMimicryDelay()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if delay < c.ServerHelloMimicryMinimumDelay || delay > c.ServerHelloMimicryMaximumDelay {
			t.Fatalf("sampled delay %v out of range [%v, %v]", delay, c.ServerHelloMimicryMinimumDelay, c.ServerHelloMimicryMaximumDelay)
		}
	}
}
