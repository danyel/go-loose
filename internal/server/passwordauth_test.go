package server

import (
	"testing"
	"time"
)

func TestLoginGuardLocksAfterFiveFailures(t *testing.T) {
	guard := newLoginGuard()
	now := time.Now()
	for range 5 {
		if !guard.allowed("address|user@example.com", now) {
			t.Fatal("guard locked too early")
		}
		guard.fail("address|user@example.com", now)
	}
	if guard.allowed("address|user@example.com", now) {
		t.Fatal("guard did not lock after five failures")
	}
	guard.success("address|user@example.com")
	if !guard.allowed("address|user@example.com", now) {
		t.Fatal("successful login did not clear failures")
	}
}
