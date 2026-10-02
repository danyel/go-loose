package server

import (
	"testing"

	"github.com/danyel/go-loose/internal/config"
)

func TestRequestTenantSlug(t *testing.T) {
	server := &Server{cfg: config.Config{AuthDomain: "auth.dev"}}
	tests := []struct {
		host string
		want string
	}{
		{host: "auth.dev", want: ""},
		{host: "auth.dev:8080", want: ""},
		{host: "nmbs.auth.dev", want: "nmbs"},
		{host: "NMBS.auth.dev:8080", want: "nmbs"},
		{host: "nested.nmbs.auth.dev", want: ""},
		{host: "localhost:8080", want: ""},
	}
	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			if got := server.requestTenantSlug(test.host); got != test.want {
				t.Fatalf("requestTenantSlug(%q) = %q, want %q", test.host, got, test.want)
			}
		})
	}
}
