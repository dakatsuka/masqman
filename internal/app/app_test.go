package app

import "testing"

func TestBanner(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = "test"

	if got, want := Banner(), "masqman test"; got != want {
		t.Fatalf("Banner() = %q, want %q", got, want)
	}
}
