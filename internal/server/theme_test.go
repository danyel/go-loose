package server

import (
	"strings"
	"testing"
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
