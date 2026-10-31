package auth

import "testing"

func TestReCreateServerReusesTheListener(t *testing.T) {
	Stop()
	ReCreateServer(Config{Listen: "127.0.0.1:0"})
	first := Listen()
	if first == "" {
		t.Fatal("listener was not created")
	}
	ReCreateServer(Config{Listen: "127.0.0.1:0"})
	second := Listen()
	Stop()
	if second != first {
		t.Fatalf("listener moved from %s to %s", first, second)
	}
}
