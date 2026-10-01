package database

import "testing"

func TestUpSection(t *testing.T) {
	got, err := upSection("-- +goose Up\nCREATE TABLE example(id int);\n-- +goose Down\nDROP TABLE example;")
	if err != nil {
		t.Fatalf("upSection() error = %v", err)
	}
	if got != "\nCREATE TABLE example(id int);\n" {
		t.Fatalf("unexpected section: %q", got)
	}
}
