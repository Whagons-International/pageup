package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/desarso/pageup/internal/api"
	"github.com/desarso/pageup/internal/client"
	"github.com/desarso/pageup/internal/pageskill"
	"github.com/desarso/pageup/internal/protocol"
	"github.com/desarso/pageup/internal/sitebundle"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pageup:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errors.New("missing HTML file")
	}
	switch args[0] {
	case "auth":
		return runAuth(args[1:])
	case "init":
		return runInit(args[1:])
	case "upload":
		return runUpload(args[1:])
	case "update":
		return runUpdate(args[1:])
	case "keys":
		return runKeys(args[1:])
	case "whoami":
		return runWhoAmI(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "public-key":
		return runPublicKey(args[1:])
	case "skill":
		return runSkill(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return nil
	default:
		return runUpload(args)
	}
}

func runAuth(args []string) error {
	if len(args) == 0 || args[0] != "login" {
		return errors.New("usage: pageup auth login [--endpoint URL] [--name DEVICE] [--no-open] [--force]")
	}
	flags := flag.NewFlagSet("auth login", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	endpoint := flags.String("endpoint", client.DefaultEndpoint, "pageup server origin")
	name := flags.String("name", defaultDeviceName(), "name for this device")
	noOpen := flags.Bool("no-open", false, "print the sign-in URL without opening a browser")
	force := flags.Bool("force", false, "replace credentials for another Pageup service")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("auth login does not accept positional arguments")
	}
	path, err := client.DefaultConfigPath()
	if err != nil {
		return err
	}

	var config client.Config
	if *force {
		config, err = client.GenerateConfig(*endpoint, *name)
		if err == nil {
			err = client.SaveConfig(path, config, true)
		}
	} else {
		config, err = client.LoadConfig(path)
		if errors.Is(err, os.ErrNotExist) || (err != nil && strings.Contains(err.Error(), "no pageup credentials")) {
			config, err = client.GenerateConfig(*endpoint, *name)
			if err == nil {
				err = client.SaveConfig(path, config, false)
			}
		} else if err == nil && strings.TrimRight(config.Endpoint, "/") != strings.TrimRight(*endpoint, "/") {
			return fmt.Errorf("existing credentials belong to %s; use --force to replace them or PAGEUP_CONFIG to keep separate Pageup identities", config.Endpoint)
		}
	}
	if err != nil {
		return err
	}
	pageup, err := client.New(config, version)
	if err != nil {
		return err
	}
	checkCtx, cancelCheck := context.WithTimeout(context.Background(), 10*time.Second)
	if key, checkErr := pageup.WhoAmI(checkCtx); checkErr == nil {
		cancelCheck()
		fmt.Printf("Already authorized as %s (%s)\n", key.Name, key.Role)
		return nil
	}
	cancelCheck()

	publicKey, err := config.PublicKey()
	if err != nil {
		return err
	}
	startCtx, cancelStart := context.WithTimeout(context.Background(), 20*time.Second)
	flow, err := pageup.StartDeviceAuth(startCtx, config.Name, protocol.EncodePublicKey(publicKey))
	cancelStart()
	if err != nil {
		return err
	}
	openTarget := printDeviceAuthInstructions(os.Stdout, flow)
	if !*noOpen {
		if err := openURL(openTarget); err != nil {
			fmt.Fprintf(os.Stderr, "pageup: could not open a browser: %v\n", err)
		}
	}
	fmt.Println("Waiting for approval...")

	interval := time.Duration(flow.IntervalSeconds) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	ctx, cancel := context.WithDeadline(context.Background(), flow.ExpiresAt.Add(5*time.Second))
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		status, err := pageup.DeviceAuthStatus(ctx, flow.ID)
		if err != nil {
			return err
		}
		switch status.Status {
		case "approved":
			fmt.Printf("Authorized %s for %s\n", config.Name, status.Email)
			return nil
		case "denied":
			return errors.New("this Google account does not have Whagons developer access")
		case "expired":
			return errors.New("Google sign-in expired; run 'pageup auth login' again")
		case "pending":
		default:
			return fmt.Errorf("unexpected authorization status %q", status.Status)
		}
		select {
		case <-ctx.Done():
			return errors.New("Google sign-in timed out; run 'pageup auth login' again")
		case <-ticker.C:
		}
	}
}

func printDeviceAuthInstructions(writer io.Writer, flow api.DeviceAuthStartResponse) string {
	openTarget := flow.VerificationURL
	if flow.UserCode != "" && flow.VerificationURI != "" {
		if flow.VerificationURLComplete != "" {
			openTarget = flow.VerificationURLComplete
		}
		fmt.Fprintln(writer, "On a computer with a browser, open:")
		fmt.Fprintln(writer, flow.VerificationURI)
		fmt.Fprintln(writer, "Enter this device code:")
		fmt.Fprintln(writer, flow.UserCode)
		return openTarget
	}
	fmt.Fprintln(writer, "Sign in with your Whagons developer Google account:")
	fmt.Fprintln(writer, flow.VerificationURL)
	return openTarget
}

func runInit(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	endpoint := flags.String("endpoint", client.DefaultEndpoint, "pageup server origin")
	name := flags.String("name", defaultDeviceName(), "name for this device")
	force := flags.Bool("force", false, "replace existing credentials")
	jsonOutput := flags.Bool("json", false, "print JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("init does not accept positional arguments")
	}
	path, err := client.DefaultConfigPath()
	if err != nil {
		return err
	}
	config, err := client.GenerateConfig(*endpoint, *name)
	if err != nil {
		return err
	}
	if err := client.SaveConfig(path, config, *force); err != nil {
		return err
	}
	publicKey, _ := config.PublicKey()
	publicKeyValue := protocol.EncodePublicKey(publicKey)
	if *jsonOutput {
		return printJSON(map[string]string{
			"config":     path,
			"endpoint":   config.Endpoint,
			"key_id":     config.KeyID,
			"public_key": publicKeyValue,
			"name":       config.Name,
		})
	}
	fmt.Printf("Created credentials: %s\n", path)
	fmt.Printf("Key ID: %s\n", config.KeyID)
	fmt.Printf("Public key: %s\n\n", publicKeyValue)
	fmt.Println("Approve this device from an already-authorized computer:")
	fmt.Printf("  pageup keys add --name %q %s\n", config.Name, publicKeyValue)
	return nil
}

func runUpload(args []string) error {
	flags := flag.NewFlagSet("upload", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	jsonOutput := flags.Bool("json", false, "print JSON")
	openPage := flags.Bool("open", false, "open the uploaded page")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: pageup [--json] [--open] <file.html|site-directory|->")
	}
	artifact, err := readArtifact(flags.Arg(0))
	if err != nil {
		return err
	}
	pageup, _, err := configuredClient()
	if err != nil {
		return err
	}
	context, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var result api.UploadResponse
	if artifact.site {
		result, err = pageup.UploadSite(context, artifact.body)
	} else {
		result, err = pageup.Upload(context, artifact.body)
	}
	if err != nil {
		return err
	}
	if *jsonOutput {
		if err := printJSON(result); err != nil {
			return err
		}
	} else {
		fmt.Println(result.URL)
	}
	if *openPage {
		return openURL(result.URL)
	}
	return nil
}

func runUpdate(args []string) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	jsonOutput := flags.Bool("json", false, "print JSON")
	openPage := flags.Bool("open", false, "open the updated page")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 2 {
		return errors.New("usage: pageup update [--json] [--open] <URL-or-UUID> <file.html|site-directory|->")
	}
	pageup, config, err := configuredClient()
	if err != nil {
		return err
	}
	id, err := parsePageID(flags.Arg(0), config.Endpoint)
	if err != nil {
		return err
	}
	artifact, err := readArtifact(flags.Arg(1))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var result api.UploadResponse
	if artifact.site {
		result, err = pageup.UpdateSite(ctx, id, artifact.body)
	} else {
		result, err = pageup.Update(ctx, id, artifact.body)
	}
	if err != nil {
		return err
	}
	if *jsonOutput {
		if err := printJSON(result); err != nil {
			return err
		}
	} else {
		fmt.Println(result.URL)
	}
	if *openPage {
		return openURL(result.URL)
	}
	return nil
}

func runKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pageup keys <add|list|revoke>")
	}
	switch args[0] {
	case "add":
		flags := flag.NewFlagSet("keys add", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		name := flags.String("name", "", "device name")
		role := flags.String("role", "upload", "upload or admin")
		jsonOutput := flags.Bool("json", false, "print JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" || flags.NArg() != 1 {
			return errors.New("usage: pageup keys add --name <device> [--role upload|admin] <public-key>")
		}
		pageup, _, err := configuredClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		key, err := pageup.AddKey(ctx, api.AddKeyRequest{Name: *name, PublicKey: flags.Arg(0), Role: *role})
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(key)
		}
		fmt.Printf("Authorized %s (%s) as %s\n", key.Name, key.ID, key.Role)
		return nil
	case "list":
		flags := flag.NewFlagSet("keys list", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		jsonOutput := flags.Bool("json", false, "print JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("usage: pageup keys list [--json]")
		}
		pageup, _, err := configuredClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		keys, err := pageup.ListKeys(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(api.KeyListResponse{Keys: keys})
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].CreatedAt.Before(keys[j].CreatedAt) })
		writer := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(writer, "ID\tNAME\tROLE\tCREATED")
		for _, key := range keys {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", key.ID, key.Name, key.Role, key.CreatedAt.Local().Format("2006-01-02 15:04"))
		}
		return writer.Flush()
	case "revoke":
		flags := flag.NewFlagSet("keys revoke", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 1 {
			return errors.New("usage: pageup keys revoke <key-id>")
		}
		pageup, _, err := configuredClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		key, err := pageup.RevokeKey(ctx, flags.Arg(0))
		if err != nil {
			return err
		}
		fmt.Printf("Revoked %s (%s)\n", key.Name, key.ID)
		return nil
	default:
		return fmt.Errorf("unknown keys command %q", args[0])
	}
}

func runWhoAmI(args []string) error {
	if len(args) != 0 {
		return errors.New("whoami does not accept arguments")
	}
	pageup, _, err := configuredClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key, err := pageup.WhoAmI(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%s (%s, %s)\n", key.Name, key.ID, key.Role)
	return nil
}

func runDoctor(args []string) error {
	if len(args) != 0 {
		return errors.New("doctor does not accept arguments")
	}
	pageup, config, err := configuredClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	health, err := pageup.Health(ctx)
	if err != nil {
		return fmt.Errorf("server health check failed: %w", err)
	}
	key, err := pageup.WhoAmI(ctx)
	if err != nil {
		return fmt.Errorf("credential check failed: %w", err)
	}
	fmt.Printf("endpoint   %s\n", config.Endpoint)
	fmt.Printf("server     %s (%s)\n", health["status"], health["version"])
	fmt.Printf("credential %s (%s, %s)\n", key.Name, key.ID, key.Role)
	return nil
}

func runPublicKey(args []string) error {
	if len(args) != 0 {
		return errors.New("public-key does not accept arguments")
	}
	config, err := client.LoadConfig("")
	if err != nil {
		return err
	}
	publicKey, err := config.PublicKey()
	if err != nil {
		return err
	}
	fmt.Println(protocol.EncodePublicKey(publicKey))
	return nil
}

func runSkill(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pageup skill <show|install>")
	}
	switch args[0] {
	case "show":
		if len(args) != 1 {
			return errors.New("usage: pageup skill show")
		}
		content, err := pageskill.SkillMarkdown()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(content)
		return err
	case "install":
		flags := flag.NewFlagSet("skill install", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		harness := flags.String("harness", "auto", "auto, codex, agents, or project")
		target := flags.String("target", "", "custom skills directory")
		force := flags.Bool("force", false, "replace embedded files in an existing Pages skill")
		jsonOutput := flags.Bool("json", false, "print JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("usage: pageup skill install [--harness auto|codex|agents|project] [--target DIR] [--force]")
		}
		root, resolvedHarness, err := resolveSkillRoot(*harness, *target)
		if err != nil {
			return err
		}
		path, err := pageskill.Install(root, *force)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(map[string]string{
				"skill":   pageskill.Name,
				"harness": resolvedHarness,
				"path":    path,
			})
		}
		fmt.Printf("Installed $%s for %s at %s\n", pageskill.Name, resolvedHarness, path)
		fmt.Println("Start a new agent session to discover the skill.")
		return nil
	default:
		return fmt.Errorf("unknown skill command %q (expected show or install)", args[0])
	}
}

func resolveSkillRoot(harness, target string) (string, string, error) {
	if target != "" {
		if harness != "" && harness != "auto" {
			return "", "", errors.New("use either --target or --harness, not both")
		}
		path, err := absoluteUserPath(target)
		return path, "custom", err
	}
	if value := strings.TrimSpace(os.Getenv("PAGEUP_SKILLS_DIR")); value != "" && (harness == "" || harness == "auto") {
		path, err := absoluteUserPath(value)
		return path, "custom", err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	if harness == "" {
		harness = "auto"
	}
	if harness == "auto" {
		if os.Getenv("CODEX_HOME") != "" {
			harness = "codex"
		} else if info, statErr := os.Stat(filepath.Join(home, ".codex")); statErr == nil && info.IsDir() {
			harness = "codex"
		} else if info, statErr := os.Stat(filepath.Join(home, ".agents")); statErr == nil && info.IsDir() {
			harness = "agents"
		} else {
			harness = "codex"
		}
	}

	var root string
	switch harness {
	case "codex":
		base := strings.TrimSpace(os.Getenv("CODEX_HOME"))
		if base == "" {
			base = filepath.Join(home, ".codex")
		}
		root = filepath.Join(base, "skills")
	case "agents":
		root = filepath.Join(home, ".agents", "skills")
	case "project":
		workingDirectory, err := os.Getwd()
		if err != nil {
			return "", "", err
		}
		root = filepath.Join(workingDirectory, ".agents", "skills")
	default:
		return "", "", fmt.Errorf("unsupported harness %q (use auto, codex, agents, project, or --target DIR)", harness)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	return root, harness, nil
}

func absoluteUserPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("skills directory cannot be empty")
	}
	if value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if value == "~" {
			value = home
		} else {
			value = filepath.Join(home, value[2:])
		}
	}
	return filepath.Abs(value)
}

func configuredClient() (*client.Client, client.Config, error) {
	config, err := client.LoadConfig("")
	if err != nil {
		return nil, client.Config{}, err
	}
	pageup, err := client.New(config, version)
	return pageup, config, err
}

type uploadArtifact struct {
	body []byte
	site bool
}

func readArtifact(path string) (uploadArtifact, error) {
	if path == "-" {
		body, err := io.ReadAll(io.LimitReader(os.Stdin, sitebundle.DefaultMaxBytes+1))
		if err != nil {
			return uploadArtifact{}, err
		}
		if int64(len(body)) > sitebundle.DefaultMaxBytes {
			return uploadArtifact{}, errors.New("HTML file exceeds the 5 MiB upload limit")
		}
		return uploadArtifact{body: body}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return uploadArtifact{}, err
	}
	if info.IsDir() {
		archive, err := sitebundle.Pack(path, sitebundle.DefaultMaxBytes)
		if err != nil {
			return uploadArtifact{}, err
		}
		return uploadArtifact{body: archive, site: true}, nil
	}
	if info.Size() > sitebundle.DefaultMaxBytes {
		return uploadArtifact{}, errors.New("HTML file exceeds the 5 MiB upload limit")
	}
	body, err := os.ReadFile(path)
	return uploadArtifact{body: body}, err
}

func parsePageID(value, endpoint string) (string, error) {
	value = strings.TrimSpace(value)
	if protocol.IsUUIDv7(value) {
		return value, nil
	}
	pageURL, err := url.Parse(value)
	if err != nil || !pageURL.IsAbs() || pageURL.User != nil {
		return "", errors.New("page must be a UUIDv7 or a Pageup URL")
	}
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("configured Pageup endpoint is invalid")
	}
	if !strings.EqualFold(pageURL.Scheme, endpointURL.Scheme) || !strings.EqualFold(pageURL.Host, endpointURL.Host) {
		return "", fmt.Errorf("page URL must belong to %s", strings.TrimRight(endpoint, "/"))
	}
	id := strings.Trim(pageURL.Path, "/")
	if !protocol.IsUUIDv7(id) {
		return "", errors.New("Pageup URL does not contain a valid UUIDv7 page id")
	}
	return id, nil
}

func openURL(value string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", value)
	case "windows":
		command = exec.Command("cmd", "/c", "start", "", value)
	default:
		command = exec.Command("xdg-open", value)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	return nil
}

func defaultDeviceName() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return "this computer"
	}
	return hostname
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `pageup — private HTML uploads, shareable URLs

Usage:
  pageup <file.html|site-directory>    upload in one command
  pageup -                            upload HTML from stdin
  pageup update URL <path|->          replace a page or site at the same URL
  pageup auth login                   authorize locally or with a headless device code
  pageup init [--endpoint URL]        create this device's key pair
  pageup keys add --name NAME PUBKEY  authorize another device
  pageup keys list                    list authorized devices
  pageup keys revoke KEY_ID           revoke a device
  pageup whoami                       show the active credential
  pageup doctor                       verify server and authentication
  pageup skill show                   print the embedded $pages skill
  pageup skill install                add $pages to this agent harness
  pageup public-key                   print this device's public key
  pageup version                      print the CLI version

Upload options (place before the file):
  --json  emit a machine-readable result
  --open  open the resulting URL

Update options (place before the URL):
  pageup update --json URL file.html  emit revision and update state as JSON
  pageup update --open UUID file.html update by id and open the page

HTML site directories:
  Include index.html at the root and up to 100 .html files total.
  Nested folders are preserved. CSS and JavaScript must remain inline;
  images and other assets must use external URLs.

Skill installation:
  pageup skill install                         auto-detect Codex or ~/.agents
  pageup skill install --harness project       install into ./.agents/skills
  pageup skill install --target /skills/root   install for any other harness
  Add --force to update an existing embedded $pages skill.`)
}
