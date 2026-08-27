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

func TestParsePageID(t *testing.T) {
	id := "019f620a-226d-7981-88d3-83da3b460b6c"
	endpoint := "https://pageup.whagons.com"
	for _, value := range []string{
		id,
		endpoint + "/" + id,
		endpoint + "/" + id + "/",
		endpoint + "/" + id + "?preview=latest#top",
	} {
		parsed, err := parsePageID(value, endpoint)
		if err != nil {
			t.Fatalf("parsePageID(%q): %v", value, err)
		}
		if parsed != id {
			t.Fatalf("parsePageID(%q) = %q", value, parsed)
		}
	}

	for _, value := range []string{
		"not-a-page",
		"https://example.com/" + id,
		endpoint + "/" + id + "/extra",
		strings.ToUpper(id),
	} {
		if _, err := parsePageID(value, endpoint); err == nil {
			t.Fatalf("parsePageID(%q) unexpectedly succeeded", value)
		}
	}
}

func TestHelpExplainsUpdatesAndEmbeddedSkill(t *testing.T) {
	var output strings.Builder
	printUsage(&output)
	for _, expected := range []string{"pageup update URL", "pageup skill install", "same URL", "site-directory", "100 .html files"} {
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
