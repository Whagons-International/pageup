package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/desarso/pageup/internal/api"
	"github.com/desarso/pageup/internal/sitebundle"
)

func TestDeviceAuthInstructionsPreferShortCode(t *testing.T) {
	flow := api.DeviceAuthStartResponse{
		UserCode:                "ABCD-EFGH",
		VerificationURI:         "https://pageup.whagons.com/auth",
		VerificationURL:         "https://pageup.whagons.com/auth/device/id",
		VerificationURLComplete: "https://pageup.whagons.com/auth?code=ABCD-EFGH",
	}
	var output strings.Builder
	openTarget := printDeviceAuthInstructions(&output, flow)
	for _, expected := range []string{flow.VerificationURI, flow.UserCode, "computer with a browser"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("device auth instructions are missing %q: %q", expected, output.String())
		}
	}
	if strings.Contains(output.String(), flow.VerificationURL) {
		t.Fatalf("device auth instructions exposed the long URL: %q", output.String())
	}
	if openTarget != flow.VerificationURLComplete {
		t.Fatalf("open target = %q", openTarget)
	}
}

func TestWhagonsExecutableUsesIsolatedConfig(t *testing.T) {
	t.Setenv("PAGEUP_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "config"))
	if err := configureWhagonsExecutableConfig("/usr/local/bin/pageup-whagons"); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "pageup-whagons", "config.json")
	if actual := os.Getenv("PAGEUP_CONFIG"); actual != expected {
		t.Fatalf("PAGEUP_CONFIG = %q, want %q", actual, expected)
	}
}

func TestLegacyExecutableKeepsExistingConfigDefault(t *testing.T) {
	t.Setenv("PAGEUP_CONFIG", "")
	if err := configureWhagonsExecutableConfig("/usr/local/bin/pageup"); err != nil {
		t.Fatal(err)
	}
	if actual := os.Getenv("PAGEUP_CONFIG"); actual != "" {
		t.Fatalf("legacy executable changed PAGEUP_CONFIG to %q", actual)
	}
}

func TestResolveSkillRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex-home"))
	t.Setenv("PAGEUP_SKILLS_DIR", "")

	root, harness, err := resolveSkillRoot("auto", "")
	if err != nil {
		t.Fatal(err)
	}
	if harness != "codex" || root != filepath.Join(home, "codex-home", "skills") {
		t.Fatalf("auto root = %q, harness = %q", root, harness)
	}

	custom, harness, err := resolveSkillRoot("auto", filepath.Join(home, "custom-skills"))
	if err != nil {
		t.Fatal(err)
	}
	if harness != "custom" || custom != filepath.Join(home, "custom-skills") {
		t.Fatalf("custom root = %q, harness = %q", custom, harness)
	}

	if _, _, err := resolveSkillRoot("codex", filepath.Join(home, "custom-skills")); err == nil {
		t.Fatal("combined harness and target unexpectedly succeeded")
	}
}

func TestResolveProjectSkillRoot(t *testing.T) {
	workingDirectory := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(previous) })

	root, harness, err := resolveSkillRoot("project", "")
	if err != nil {
		t.Fatal(err)
	}
	if harness != "project" || root != filepath.Join(workingDirectory, ".agents", "skills") {
		t.Fatalf("project root = %q, harness = %q", root, harness)
	}
}

func TestParseTarget(t *testing.T) {
	id := "019f620a-226d-7981-88d3-83da3b460b6c"
	endpoint := "https://pageup.whagons.com"
	for value, expected := range map[string]targetKind{
		id:                                     targetAny,
		endpoint + "/" + id:                    targetPage,
		endpoint + "/" + id + "/":              targetPage,
		endpoint + "/" + id + "?preview=1#top": targetPage,
		endpoint + "/f/" + id:                  targetFile,
		endpoint + "/f/" + id + "/report.pdf":  targetFile,
		endpoint + "/f/" + id + "/a%20b.png":   targetFile,
	} {
		parsed, kind, err := parseTarget(value, endpoint)
		if err != nil {
			t.Fatalf("parseTarget(%q): %v", value, err)
		}
		if parsed != id || kind != expected {
			t.Fatalf("parseTarget(%q) = %q, %d", value, parsed, kind)
		}
	}

	for _, value := range []string{
		"not-a-page",
		"https://example.com/" + id,
		"https://example.com/f/" + id + "/report.pdf",
		endpoint + "/" + id + "/extra",
		endpoint + "/f/not-a-file/report.pdf",
		strings.ToUpper(id),
	} {
		if _, _, err := parseTarget(value, endpoint); err == nil {
			t.Fatalf("parseTarget(%q) unexpectedly succeeded", value)
		}
	}
}

func TestIsHostedFileRoutesNonHTMLFiles(t *testing.T) {
	root := t.TempDir()
	cases := map[string]struct {
		contents string
		hosted   bool
	}{
		"report.html": {"<h1>report</h1>", false},
		"legacy.HTM":  {"<h1>legacy</h1>", false},
		"screen.png":  {"\x89PNG\r\n\x1a\n", true},
		"notes.txt":   {"<h1>plain text anyway</h1>", true},
		"tmp-html":    {"<!doctype html><title>x</title>", false},
		"tmp-log":     {"build succeeded\n", true},
		"empty-noext": {"", true},
		"archive.zip": {"PK\x03\x04", true},
	}
	for name, test := range cases {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
			t.Fatal(err)
		}
		hosted, err := isHostedFile(path)
		if err != nil {
			t.Fatalf("isHostedFile(%q): %v", name, err)
		}
		if hosted != test.hosted {
			t.Fatalf("isHostedFile(%q) = %v", name, hosted)
		}
	}
	if hosted, err := isHostedFile(root); err != nil || hosted {
		t.Fatalf("directory hosted = %v, %v", hosted, err)
	}
	if hosted, err := isHostedFile("-"); err != nil || hosted {
		t.Fatalf("stdin hosted = %v, %v", hosted, err)
	}
	if _, _, err := openFileContent(root); err == nil || !strings.Contains(err.Error(), "archive it first") {
		t.Fatalf("directory file content error = %v", err)
	}
}

func TestHelpExplainsUpdatesAndEmbeddedSkill(t *testing.T) {
	var output strings.Builder
	printUsage(&output)
	for _, expected := range []string{"pageup-whagons update URL", "pageup-whagons skill install", "same URL", "site-directory", "100 .html files", "pageup-whagons file <path...|->", "pageup-whagons delete FILE_URL", "?download"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("help is missing %q", expected)
		}
	}
}

func TestReadArtifactPacksHTMLDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("index"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "index.html"), []byte("docs"), 0o600); err != nil {
		t.Fatal(err)
	}

	artifact, err := readArtifact(root)
	if err != nil {
		t.Fatal(err)
	}
	if !artifact.site {
		t.Fatal("directory was not recognized as an HTML site")
	}
	parsed, err := sitebundle.Parse(artifact.body, sitebundle.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Files["index.html"]) != "index" || string(parsed.Files["docs/index.html"]) != "docs" {
		t.Fatalf("unexpected packed site: %#v", parsed.Files)
	}
}
