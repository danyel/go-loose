package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/danyel/go-loose/web"
)

// The theme origin is substituted into every HTML page. These tests cover the two
// branches and the failure mode in between, because a wrong result here is invisible
// until a user reports that the theme stopped applying.

const pageWithThemeLines = `<!doctype html>
<html data-theme="tokyo" data-mode="dark">
<head>
  <link rel="stylesheet" href="/assets/style.css">
  <link rel="stylesheet" href="__GO_LOOSE_THEME_ORIGIN__/rt/v1/contract.css" data-theme-contract>
</head>
<body>
  <bananas-theme-selector id="theme"></bananas-theme-selector>
  <script type="module" src="__GO_LOOSE_THEME_ORIGIN__/rt/v1/components.js" data-bananas-components></script>
</body>
</html>`

func TestThemeOriginIsSubstituted(t *testing.T) {
	got := string(applyThemeOrigin([]byte(pageWithThemeLines), "https://themes.example.com"))

	if strings.Contains(got, themeOriginPlaceholder) {
		t.Error("the placeholder survived substitution")
	}
	if !strings.Contains(got, `href="https://themes.example.com/rt/v1/contract.css"`) {
		t.Errorf("the contract stylesheet was not rewritten:\n%s", got)
	}
	if !strings.Contains(got, `src="https://themes.example.com/rt/v1/components.js"`) {
		t.Errorf("the component module was not rewritten:\n%s", got)
	}
	// The application's own stylesheet must be untouched.
	if !strings.Contains(got, `href="/assets/style.css"`) {
		t.Error("the local stylesheet was rewritten")
	}
}

func TestThemeOriginTrailingSlashIsTrimmed(t *testing.T) {
	// A trailing slash would produce a double slash, and the service answers 404 for
	// "//rt/v1/contract.css" because the route is matched on the clean path.
	for _, base := range []string{
		"https://themes.example.com/",
		"https://themes.example.com///",
	} {
		got := string(applyThemeOrigin([]byte(pageWithThemeLines), base))
		if strings.Contains(got, "com//") {
			t.Errorf("base %q produced a doubled slash:\n%s", base, got)
		}
	}
}

func TestThemeLinesAreDroppedWhenNoOriginIsConfigured(t *testing.T) {
	for _, base := range []string{"", "   ", "/"} {
		got := string(applyThemeOrigin([]byte(pageWithThemeLines), base))

		if strings.Contains(got, themeOriginPlaceholder) {
			t.Errorf("base %q left the placeholder in place:\n%s", base, got)
		}
		// An empty href would be a same-origin request to this application, which 404s
		// and looks like a styling bug in the wrong service.
		if strings.Contains(got, `href="/rt/v1/contract.css"`) {
			t.Errorf("base %q emitted an empty contract href:\n%s", base, got)
		}
		if strings.Contains(got, themeMarkerContract) || strings.Contains(got, themeMarkerScript) {
			t.Errorf("base %q left a theme line behind:\n%s", base, got)
		}
		// The rest of the page must survive.
		if !strings.Contains(got, `href="/assets/style.css"`) {
			t.Errorf("base %q removed the local stylesheet:\n%s", base, got)
		}
		if !strings.Contains(got, "<body>") || !strings.Contains(got, "</html>") {
			t.Errorf("base %q damaged the page structure:\n%s", base, got)
		}
	}
}

func TestThemeOriginLeavesNonThemePagesAlone(t *testing.T) {
	// A page with no theme lines must come back byte-identical, so that a deployment
	// without the contract serving its login and install pages is a no-op.
	plain := []byte("<!doctype html>\n<html>\n<body>no theme here</body>\n</html>\n")
	if got := applyThemeOrigin(plain, "https://themes.example.com"); string(got) != string(plain) {
		t.Errorf("a page without theme lines was modified:\n%s", got)
	}
	if got := applyThemeOrigin(plain, ""); string(got) != string(plain) {
		t.Errorf("a page without theme lines was modified:\n%s", got)
	}
}

// contractBackedTokens maps this application's own colour token onto the shared
// contract role that carries the same meaning. The right-hand side is a bare role
// name because the variable prefix belongs to the contract.
var contractBackedTokens = map[string]string{
	"--bg":      "bg",
	"--surface": "surface",
	// go-loose's second surface step is the contract's raised surface.
	"--surface2": "surface-raised",
	"--text":     "text",
	"--muted":    "muted",
	"--accent":   "accent",
	// go-loose's secondary accent is the contract's secondary role: for every
	// palette the two agree, tokyo's #bb9af7 and catppuccin's #cba6f7 among them.
	"--accent2": "secondary",
	"--good":    "good",
	"--danger":  "danger",
	"--border":  "border",
}

// TestLocalTokensAdoptTheContractWhereItIsServed covers the difference between a
// theme selector that is present in the page and one that works.
//
// Every palette this application names has to resolve through the contract's
// variables, with this application's own value as the fallback. The fallback is
// what keeps the install and login pages styled as they always were: they never load
// the contract, so the variable is undefined there and the literal applies. Loading
// the contract on a console page therefore adopts the shared palette without
// changing anything for the pages that do not ask for it.
//
// Both directions are asserted. Adopting the role is not enough on its own: a single
// declaration left holding a bare literal overrides the contract for whichever
// palette that block names, and the console then renders half shared and half local.
func TestLocalTokensAdoptTheContractWhereItIsServed(t *testing.T) {
	css, err := web.Files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("style.css must be embedded: %v", err)
	}
	stylesheet := string(css)

	for token, role := range contractBackedTokens {
		if !strings.Contains(stylesheet, fmt.Sprintf("%s:var(--bn-%s,", token, role)) {
			t.Errorf("token %s does not adopt --bn-%s, so selecting a palette outside this application's own four changes nothing:\n%s",
				token, role, firstLines(css, 8))
		}
		// A literal assignment anywhere would win for the palette it sits under, and
		// the contract's value for that one palette would be discarded.
		if literal := token + ":#"; strings.Contains(stylesheet, literal) {
			t.Errorf("token %s is still assigned a bare literal, which overrides the contract for the palette that block names:\n%s",
				token, firstLines(css, 8))
		}
	}
}

// TestTheShadowTokenIsNotMapped guards the one token deliberately left alone.
// The contract's shadow family holds complete box-shadow values, and this token
// holds a colour, so wiring them together would substitute a shadow for a colour.
func TestTheShadowTokenIsNotMapped(t *testing.T) {
	css, err := web.Files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("style.css must be embedded: %v", err)
	}
	if strings.Contains(string(css), "--shadow:var(--bn-") {
		t.Error("--shadow is a colour here and the contract's shadow roles are box-shadow values; mapping them would break every elevation")
	}
}

// firstLines trims a stylesheet for an error message, since the token blocks sit at
// the top of the file and the whole of it is noise in a test failure.
func firstLines(css []byte, n int) string {
	lines := strings.SplitN(string(css), "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
