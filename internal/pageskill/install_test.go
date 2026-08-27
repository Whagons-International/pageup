package pageskill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallAndReplaceEmbeddedSkill(t *testing.T) {
	root := t.TempDir()
	destination, err := Install(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if destination != filepath.Join(root, Name) {
		t.Fatalf("destination = %q", destination)
	}

	skill, err := os.ReadFile(filepath.Join(destination, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(skill), "name: pages") || !strings.Contains(string(skill), "pageup auth login") || !strings.Contains(string(skill), "https://pageup.whagons.com/install.sh") {
		t.Fatal("installed skill is missing expected Pages instructions")
	}
	metadata, err := os.ReadFile(filepath.Join(destination, "agents", "openai.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metadata), `display_name: "Pages"`) {
		t.Fatal("installed skill metadata is incomplete")
	}
	if _, err := Install(root, false); err == nil {
		t.Fatal("second install unexpectedly replaced an existing skill")
	}

	if err := os.WriteFile(filepath.Join(destination, "SKILL.md"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(root, true); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(filepath.Join(destination, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := SkillMarkdown()
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(embedded) {
		t.Fatal("force install did not restore the embedded skill")
	}
	info, err := os.Stat(filepath.Join(destination, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("skill mode = %o", info.Mode().Perm())
	}
}
