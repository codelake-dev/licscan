package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/codelake-dev/licscan/internal/version"
)

const (
	releaseAPI  = "https://api.github.com/repos/codelake-dev/licscan/releases/latest"
	cdnBaseURL  = "https://install.codelake.dev/licscan"
	downloadURL = "https://github.com/codelake-dev/licscan/releases/download"
)

func newUpdateCommand() *cobra.Command {
	var check bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update licscan to the latest version",
		Long: `Checks GitHub for the latest release and replaces the current binary
in-place. Use --check to only check without downloading.

If installed via Homebrew, use 'brew upgrade licscan' instead.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdate(cmd, check)
		},
	}

	cmd.Flags().BoolVar(&check, "check", false, "only check for updates, don't install")

	return cmd
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

func runUpdate(cmd *cobra.Command, checkOnly bool) error {
	w := cmd.ErrOrStderr()

	current := version.Short()
	_, _ = fmt.Fprintf(w, "  Current version: %s\n", current)
	_, _ = fmt.Fprintf(w, "  Checking for updates...\n")

	latest, err := fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("check for updates: %w", err)
	}

	if current == latest.TagName || "v"+current == latest.TagName || current == "v"+latest.TagName {
		_, _ = fmt.Fprintf(w, "  ✓ Already up to date (%s)\n", latest.TagName)
		return nil
	}

	if current == "dev" {
		_, _ = fmt.Fprintf(w, "  Latest release: %s\n", latest.TagName)
		_, _ = fmt.Fprintf(w, "  ⚠ Running a dev build. Use `go install` or download from:\n")
		_, _ = fmt.Fprintf(w, "    %s\n", latest.HTMLURL)
		return nil
	}

	_, _ = fmt.Fprintf(w, "  New version available: %s → %s\n", current, latest.TagName)

	if checkOnly {
		_, _ = fmt.Fprintf(w, "  Run `licscan update` to install.\n")
		return nil
	}

	binaryName := buildBinaryName()
	url := fmt.Sprintf("%s/%s/%s", cdnBaseURL, latest.TagName, binaryName)

	_, _ = fmt.Fprintf(w, "  Downloading %s...\n", binaryName)

	tmpFile, err := downloadBinary(url)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer os.Remove(tmpFile)

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find current binary: %w", err)
	}

	execPath = resolveSymlink(execPath)

	info, err := os.Stat(execPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", execPath, err)
	}

	if err := os.Rename(tmpFile, execPath); err != nil {
		return fmt.Errorf("replace binary: %w (try running with sudo)", err)
	}

	if err := os.Chmod(execPath, info.Mode()); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	_, _ = fmt.Fprintf(w, "  ✓ Updated to %s (%s)\n", latest.TagName, execPath)
	return nil
}

func fetchLatestRelease() (*ghRelease, error) {
	req, err := http.NewRequest(http.MethodGet, releaseAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &rel, nil
}

func buildBinaryName() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	suffix := goos + "-" + goarch
	if goos == "windows" {
		return "licscan-" + suffix + ".exe"
	}
	return "licscan-" + suffix
}

func downloadBinary(url string) (string, error) {
	resp, err := http.Get(url) //nolint:gosec // URL is constructed from constants + GitHub release tag
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "licscan-update-*")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()

	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}

	return tmp.Name(), nil
}

func resolveSymlink(path string) string {
	for i := 0; i < 10; i++ {
		target, err := os.Readlink(path)
		if err != nil {
			return path
		}
		if !strings.HasPrefix(target, "/") {
			dir := path[:strings.LastIndex(path, "/")+1]
			target = dir + target
		}
		path = target
	}
	return path
}
