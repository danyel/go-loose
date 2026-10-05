package server

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danyel/go-loose/internal/password"
	"golang.org/x/oauth2"
)

func (s *Server) configureOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURL string) error {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("discover OIDC provider: %w", err)
	}
	config := &oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret,
		Endpoint: provider.Endpoint(), RedirectURL: redirectURL,
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	s.authMu.Lock()
	s.oauth = config
	s.verifier = provider.Verifier(&oidc.Config{ClientID: clientID})
	// The logout endpoint is not part of the OAuth endpoint set, so it is read out
	// of the discovery document separately. A provider that does not advertise one
	// leaves this empty, which is what makes signing out fall back to clearing the
	// local session alone.
	s.endSession = providerLogoutEndpoint(provider)
	s.authMu.Unlock()
	return nil
}

// providerLogoutEndpoint reads end_session_endpoint out of an OIDC discovery
// document, returning an empty string when the provider does not advertise one.
func providerLogoutEndpoint(provider *oidc.Provider) string {
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return ""
	}
	return claims.EndSessionEndpoint
}

// logoutConfiguration returns what is needed to end a session at the identity
// provider: the discovered endpoint and the client it would be requested for.
func (s *Server) logoutConfiguration() (endpoint, clientID string) {
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	if s.oauth != nil {
		clientID = s.oauth.ClientID
	}
	return s.endSession, clientID
}

func (s *Server) oidcConfiguration() (*oauth2.Config, *oidc.IDTokenVerifier) {
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	return s.oauth, s.verifier
}

func (s *Server) hasOIDC() bool {
	config, verifier := s.oidcConfiguration()
	return config != nil && verifier != nil
}

func (s *Server) ensureLocalAdministrator(ctx context.Context) error {
	if !s.cfg.LocalLogin {
		return nil
	}
	dummyHash, err := password.Hash("not-a-real-account-password")
	if err != nil {
		return fmt.Errorf("hash password timing value: %w", err)
	}
	s.loginGuard.dummyHash = dummyHash
	if s.cfg.LocalAdminPassword == "" {
		return nil
	}
	passwordHash, err := password.Hash(s.cfg.LocalAdminPassword)
	if err != nil {
		return fmt.Errorf("hash local administrator password: %w", err)
	}
	if err := s.store.EnsurePasswordUser(
		ctx, s.cfg.LocalAdminEmail, "Local Administrator", passwordHash,
		s.cfg.BootstrapTenant, s.cfg.BootstrapApp,
	); err != nil {
		return fmt.Errorf("bootstrap local administrator: %w", err)
	}
	return nil
}
