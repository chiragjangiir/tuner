// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

const rawSecret = "supersecret-db-pass"

// leakySite serves an exposed .env and real 404s for everything else.
func leakySite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte("<html>home</html>"))
		case "/.env":
			w.Write([]byte("APP_NAME=Shop\nDB_PASSWORD=" + rawSecret + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cleanSite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		for k, v := range map[string]string{
			"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
			"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
		} {
			w.Header().Set(k, v)
		}
		w.Write([]byte("<html>home</html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// tuner runs the CLI in process. Scans get --rate 0 and, unless the test
// sets --retries, --retries 0, so a target that is down fails at once
// instead of after two backed-off retries.
func tuner(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	if len(args) > 0 && args[0] == "scan" {
		args = append(args, "--rate", "0")
		if !slices.ContainsFunc(args, func(a string) bool { return a == "--retries" || strings.HasPrefix(a, "--retries=") }) {
			args = append(args, "--retries", "0")
		}
	}
	return tunerExact(t, args...)
}

// realTempDir is t.TempDir with its links and short names resolved, the
// way a local scan reports its folder: on macOS the temp folder is under
// the /var link to /private/var. On Windows it can be a short name like
// RUNNER~1.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// testCacheHome marks a test that already set its cache folder.
const testCacheHome = "TUNER_TEST_CACHE_HOME"

// setCacheHome points os.UserCacheDir at dir on every OS: XDG_CACHE_HOME
// on Linux, HOME on macOS (~/Library/Caches) and LocalAppData on Windows,
// which ignore XDG_CACHE_HOME. It returns the folder os.UserCacheDir now
// gives, which the vulnerability and check pack caches live under.
func setCacheHome(t *testing.T, dir string) string {
	t.Helper()
	t.Setenv(testCacheHome, dir)
	t.Setenv("XDG_CACHE_HOME", dir)
	switch runtime.GOOS {
	case "darwin", "ios":
		t.Setenv("HOME", dir)
	case "windows":
		t.Setenv("LocalAppData", dir)
	}
	d, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// tunerExact is tuner without the added --rate 0 and --retries 0, for
// tests of the command line itself.
func tunerExact(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // keep the first-run marker out of the real config
	if os.Getenv(testCacheHome) == "" {
		setCacheHome(t, t.TempDir()) // and the vulnerability cache
	}
	// Never reach the real APIs or the check pack release from tests. Each
	// one a test points at its own server is left alone.
	for _, name := range []string{"TUNER_VULN_API", "TUNER_WPORG_API", "TUNER_PHPNET_API", "TUNER_OSV_API", "TUNER_WORDFENCE_API", "TUNER_WPDL_API", "TUNER_CHECKS_URL"} {
		if os.Getenv(name) == "" {
			t.Setenv(name, "http://127.0.0.1:1")
		}
	}
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestScanJSON(t *testing.T) {
	srv := leakySite(t)
	code, out, errs := tuner(t, "scan", srv.URL, "--json")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var rep struct {
		Schema   string
		Score    int
		Findings []struct{ ID string }
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if rep.Schema != "rhythm-tuner/v0" || !hasFinding(rep.Findings, "leak-dotenv") || rep.Score >= 100 {
		t.Errorf("unexpected report: %+v", rep)
	}
	if strings.Contains(out, rawSecret) {
		t.Error("JSON output leaks the raw secret")
	}
}

func hasFinding(fs []struct{ ID string }, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestOutputFiles(t *testing.T) {
	srv := leakySite(t)
	dir := t.TempDir()
	for _, name := range []string{"r.sarif", "r.md", "r.json", "r.jsonl"} {
		path := filepath.Join(dir, name)
		code, out, errs := tuner(t, "scan", srv.URL, "-o", path, "--plain")
		if code != exitOK {
			t.Fatalf("%s: exit %d: %s", name, code, errs)
		}
		if !strings.Contains(out, ".env file exposed") {
			t.Errorf("%s: live view missing while writing a file:\n%s", name, out)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), rawSecret) {
			t.Errorf("%s leaks the raw secret", name)
		}
		if !strings.Contains(string(data), "leak-dotenv") {
			t.Errorf("%s has no leak-dotenv finding:\n%s", name, data)
		}
	}
	var sarif struct {
		Version string
		Runs    []struct {
			Results []struct{ RuleID, Level string }
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "r.sarif"))
	if err := json.Unmarshal(data, &sarif); err != nil || sarif.Version != "2.1.0" || len(sarif.Runs) != 1 {
		t.Errorf("bad SARIF: %v", err)
	}
}

func TestFailOnAndBaseline(t *testing.T) {
	srv := leakySite(t)
	if code, _, _ := tuner(t, "scan", srv.URL, "--json", "--fail-on", "high"); code != exitFindings {
		t.Errorf("--fail-on high with a critical finding: exit %d, want %d", code, exitFindings)
	}
	clean := cleanSite(t)
	if code, _, errs := tuner(t, "scan", clean.URL, "--json", "--fail-on", "high"); code != exitOK {
		t.Errorf("--fail-on high on a site with only medium findings: exit %d: %s", code, errs)
	}

	base := filepath.Join(t.TempDir(), "baseline.json")
	if code, _, errs := tuner(t, "scan", srv.URL, "-o", base, "-q"); code != exitOK {
		t.Fatalf("writing baseline: exit %d: %s", code, errs)
	}
	code, out, _ := tuner(t, "scan", srv.URL, "--json", "--baseline", base, "--fail-on", "info")
	if code != exitOK || strings.Contains(out, "leak-dotenv") {
		t.Errorf("baselined findings still reported (exit %d)", code)
	}
}

func TestBatch(t *testing.T) {
	a, b := leakySite(t), cleanSite(t)
	list := filepath.Join(t.TempDir(), "sites.txt")
	os.WriteFile(list, []byte("# agency sites\n"+a.URL+"\n\n"+b.URL+"  # client B\n"+a.URL+"\n"), 0o644)
	code, out, errs := tuner(t, "scan", "-l", list, "--json")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var reps []struct{ Target string }
	if err := json.Unmarshal([]byte(out), &reps); err != nil || len(reps) != 2 {
		t.Fatalf("want 2 reports (duplicates removed), got %d: %v", len(reps), err)
	}
}

func TestUnreachableTarget(t *testing.T) {
	srv := leakySite(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	code, out, errs := tuner(t, "scan", srv.URL, dead.URL, "--json")
	if code != exitError || !strings.Contains(errs, "can't reach") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if !strings.Contains(out, "leak-dotenv") {
		t.Error("the reachable target's report is missing")
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{"scan"},
		{"scan", "example.com", "--json", "--sarif"},
		{"scan", "example.com", "-H", "no colon"},
		{"scan", "./no-such-dir"},
		{"scan", "example.com", "--profile", "turbo"},
		{"scan", "example.com", "--fail-on", "urgent"},
		{"scan", "example.com", "--proxy", "ftp://x"},
		{"scan", "example.com", "-o", "report.txt"},
		{"scan", "example.com", "--id", "nope-*"},
		{"bogus"},
	}
	for _, args := range cases {
		if code, _, _ := tuner(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

func TestChecksCommand(t *testing.T) {
	code, out, _ := tuner(t, "checks", "--tags", "tls")
	if code != exitOK || !strings.Contains(out, "tls-cert-expired") || strings.Contains(out, "leak-dotenv") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestVulnScan(t *testing.T) {
	var apiHits atomic.Int32
	var apiDown atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		if apiDown.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/plugin/contact-form-7/":
			w.Write([]byte(`{"error":0,"data":{"name":"Contact Form 7","closed":0,"vulnerability":[{"uuid":"u1",
				"operator":{"max_version":"5.3.2","max_operator":"lt","unfixed":"0"},
				"source":[{"id":"CVE-2020-35489","name":"CVE-2020-35489","link":"https://www.cve.org/x"}],
				"impact":{"cvss3":{"score":"10.0","severity":"critical"},"kev":false}}]}}`))
		case "/plugins/info/1.2/":
			w.Write([]byte(`{"version":"6.2.3","last_updated":"2026-10-21 8:43am GMT"}`))
		default:
			w.Write([]byte(`{"error":0,"data":{"vulnerability":[]}}`))
		}
	}))
	defer api.Close()
	t.Setenv("TUNER_VULN_API", api.URL)
	t.Setenv("TUNER_WPORG_API", api.URL)
	t.Setenv("TUNER_PHPNET_API", api.URL)
	setCacheHome(t, t.TempDir())
	packRelease(t, packCheck, "0.2.0") // so update's check pack refresh succeeds

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<link href="/wp-content/plugins/contact-form-7/s.css?ver=5.3.1">`))
		case "/wp-content/plugins/contact-form-7/readme.txt":
			w.Write([]byte("Stable tag: 5.3.1\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()

	code, out, errs := tuner(t, "scan", site.URL, "--md")
	if code != exitOK || !strings.Contains(out, "contact-form-7 5.3.1: 1 known vulnerability") ||
		!strings.Contains(out, "CVE-2020-35489") || !strings.Contains(out, "WPVulnerability") {
		t.Fatalf("exit %d, stderr %s\n%s", code, errs, out)
	}

	// Cached now: offline works with the API down and makes no requests.
	apiDown.Store(true)
	hits := apiHits.Load()
	code, out, _ = tuner(t, "scan", site.URL, "--json", "--offline", "--id", "vuln-*")
	if code != exitOK || !strings.Contains(out, "vuln-plugin-contact-form-7") || strings.Contains(out, "hdr-") {
		t.Errorf("offline --id vuln-*: exit %d\n%s", code, out)
	}
	if apiHits.Load() != hits {
		t.Error("--offline made requests")
	}

	// update keeps cached copies when the API fails and says so.
	if code, out, _ := tuner(t, "update"); code != exitError || !strings.Contains(out, "failed; cached copies kept") {
		t.Errorf("update with API down: exit %d\n%s", code, out)
	}
	apiDown.Store(false)
	if code, out, _ := tuner(t, "update"); code != exitOK || !strings.Contains(out, "Refreshed 2 vulnerability records") {
		t.Errorf("update: exit %d\n%s", code, out)
	}
	if code, _, _ := tuner(t, "scan", site.URL, "--json", "--no-vulns", "--id", "vuln-*"); code != exitUsage {
		t.Errorf("--no-vulns with only vuln ids should be a usage error, got %d", code)
	}
}

func TestUpdateNotice(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v9.0.0","assets":[]}`))
	}))
	defer gh.Close()
	t.Setenv("RHYTHM_GITHUB_API", gh.URL)
	t.Setenv("CI", "")
	t.Setenv("RHYTHM_NO_UPDATE_CHECK", "")
	old := version
	version = "0.1.0"
	defer func() { version = old }()

	_, _, errs := tuner(t, "scan", cleanSite(t).URL, "--plain")
	if !strings.Contains(errs, "0.1.0 → 9.0.0") || !strings.Contains(errs, "rhythm update") {
		t.Errorf("no update notice in stderr:\n%s", errs)
	}
	t.Setenv("RHYTHM_NO_UPDATE_CHECK", "1")
	if _, _, errs := tuner(t, "scan", cleanSite(t).URL, "--plain"); strings.Contains(errs, "new release") {
		t.Error("RHYTHM_NO_UPDATE_CHECK ignored")
	}
}

func TestChecksHelpAndFooter(t *testing.T) {
	code, out, _ := tuner(t, "checks", "--help")
	if code != exitOK || !strings.Contains(out, `--profile <name>     quick or default (default: every check)`) {
		t.Errorf("checks --help: exit %d\n%s", code, out)
	}
	if code, _, errs := tuner(t, "checks", "--bogus"); code != exitUsage || !strings.Contains(errs, "Usage:") {
		t.Errorf("checks --bogus: exit %d\n%s", code, errs)
	}
	_, out, _ = tuner(t, "checks", "--id", "leak-dotenv", "--no-check-updates")
	if !strings.Contains(out, "1 check, plus") || !strings.Contains(out, "which scans skip with --no-vulns") {
		t.Errorf("footer:\n%s", out)
	}
}

func TestKnownExploitedTagSelectsVulnMatching(t *testing.T) {
	if code, _, errs := tuner(t, "scan", cleanSite(t).URL, "--tags", "known-exploited", "--json"); code != exitOK {
		t.Errorf("--tags known-exploited: exit %d: %s", code, errs)
	}
}

// A batch gives an array even when only one site could be scanned, so
// scripts can always loop over the result.
func TestBatchJSONStaysArray(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	_, out, _ := tuner(t, "scan", cleanSite(t).URL, dead.URL, "--json")
	var reps []struct{ Target, Error, Schema string }
	if err := json.Unmarshal([]byte(out), &reps); err != nil || len(reps) != 2 {
		t.Fatalf("want an array with both sites, got %v:\n%.200s", err, out)
	}
	if reps[0].Schema == "" || reps[0].Error != "" || reps[1].Target != dead.URL || !strings.Contains(reps[1].Error, "can't reach") {
		t.Errorf("want the report then an error entry for the dead site, got %+v", reps)
	}
}

func TestClassifyTarget(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, d := range []string{"example.com", "wordpress", "sites/shop"} {
		os.MkdirAll(d, 0o755)
	}
	cases := []struct {
		target    string
		local     bool
		ambiguous bool
	}{
		{"example.com", false, true},
		{"wordpress", false, true},
		{"./example.com", true, false},
		{"../example.com", true, false},
		{".", true, false},
		{"..", true, false},
		{"~", true, false},
		{"~/sites/shop", true, false},
		{"/var/www/example.com", true, false},
		{`C:\inetpub\wwwroot`, true, false},
		{"c:/sites", true, false},
		{`.\example.com`, true, false},
		{"sites/shop", true, false},
		{"sites/missing", true, false}, // a path, so local.Root reports it missing
		{"https://example.com", false, false},
		{"http://example.com/blog", false, false},
		{"example.org", false, false},       // no folder by that name
		{"example.org/blog", false, false},  // host and path
		{"localhost:8080/wp", false, false}, // host with a port
		{"example.com/blog", false, false},  // no folder by that path
		{"127.0.0.1:20220", false, false},   // not a drive letter
	}
	for _, c := range cases {
		local, err := classifyTarget(c.target)
		if local != c.local || (err != nil) != c.ambiguous {
			t.Errorf("%s: local %v, err %v; want local %v, ambiguous %v", c.target, local, err, c.local, c.ambiguous)
		}
	}
}

// A folder named like the site must not turn a remote scan into a local
// one, or the other way round.
func TestFolderNamedLikeHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("folder names can't hold a colon")
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	t.Chdir(t.TempDir())
	for _, d := range []string{host, "example.com"} {
		os.MkdirAll(filepath.Join(d, "wp-includes"), 0o755)
		os.WriteFile(filepath.Join(d, "wp-includes", "version.php"), []byte("<?php $wp_version = '6.4.1';"), 0o600)
	}

	for _, target := range []string{"example.com", host} {
		code, _, errs := tuner(t, "scan", target, "--json")
		want := target + " is both a folder here and a hostname; use ./" + target + " or https://" + target
		if code != exitUsage || !strings.Contains(errs, want) {
			t.Errorf("%s: exit %d, stderr %q", target, code, errs)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("an ambiguous target sent %d requests", hits.Load())
	}

	code, out, errs := tuner(t, "scan", "./"+host, "--json", "--no-vulns", "--php", "/nonexistent/php")
	if code != exitOK || !strings.Contains(out, `"wordpress_version": "6.4.1"`) || hits.Load() != 0 {
		t.Errorf("./%s: exit %d, %d requests, stderr %s\n%.300s", host, code, hits.Load(), errs, out)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--json", "--no-vulns"); code != exitOK || hits.Load() == 0 {
		t.Errorf("%s: exit %d, %d requests: %s", srv.URL, code, hits.Load(), errs)
	}
	p, err := planScan([]string{"https://example.com", "--no-vulns", "--no-check-updates"}, nil)
	if err != nil || isLocalPath(p.targets[0]) {
		t.Errorf("https://example.com: %v", err)
	}
}

// hangingSite answers the home page, then holds every other request until
// the test ends, so a scan is reliably still running when the test stops it.
func hangingSite(t *testing.T) (srv *httptest.Server, started <-chan struct{}) {
	t.Helper()
	release, start := make(chan struct{}), make(chan struct{})
	var once sync.Once
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("<html>home</html>"))
			return
		}
		once.Do(func() { close(start) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first
	return srv, start
}

const oldReport = `{"previous": "report"}`

func writeOld(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(oldReport), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertOld(t *testing.T, path string) {
	t.Helper()
	if data, err := os.ReadFile(path); err != nil || string(data) != oldReport {
		t.Errorf("previous report changed: %q, %v", data, err)
	}
}

func TestReportReplacedOnlyWhenComplete(t *testing.T) {
	path := writeOld(t)
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", path, "-q"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	data, _ := os.ReadFile(path)
	fi, _ := os.Stat(path)
	// The kept mode only shows where files have Unix modes.
	if !strings.Contains(string(data), "leak-dotenv") || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640) {
		t.Errorf("report not replaced (mode %v):\n%.200s", fi.Mode(), data)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp")); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestReportKeptWhenEveryTargetFails(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	for _, name := range []string{"report.json", "report.jsonl"} {
		path := filepath.Join(t.TempDir(), name)
		os.WriteFile(path, []byte(oldReport), 0o600)
		code, _, errs := tuner(t, "scan", dead.URL, "-o", path, "--retries", "0")
		if code != exitError || !strings.Contains(errs, "rhythm tuner scan: no report written to "+path+": every target failed; it keeps the previous report") {
			t.Errorf("%s: exit %d, stderr %q", name, code, errs)
		}
		if data, _ := os.ReadFile(path); string(data) != oldReport {
			t.Errorf("%s replaced: %q", name, data)
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp")); len(left) > 0 {
			t.Errorf("temporary files left: %v", left)
		}
	}
}

// --html follows the -o rule: when every target failed, the previous
// HTML report stays and stderr names it. A missing file isn't created.
func TestHTMLKeptWhenEveryTargetFails(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	dir := t.TempDir()
	page, path := filepath.Join(dir, "keep.html"), filepath.Join(dir, "r.json")
	const oldPage = "<!doctype html><p>last night's report</p>"
	os.WriteFile(page, []byte(oldPage), 0o600)
	os.WriteFile(path, []byte(oldReport), 0o600)
	code, _, errs := tuner(t, "scan", dead.URL, "--html", page, "-o", path, "--retries", "0")
	if code != exitError {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	for _, want := range []string{
		"no report written to " + path + ": every target failed; it keeps the previous report",
		"no HTML report written to " + page + ": every target failed; it keeps the previous report",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	if data, _ := os.ReadFile(page); string(data) != oldPage {
		t.Errorf("HTML report replaced: %.200q", data)
	}
	if strings.Contains(errs, "\nHTML report written to") {
		t.Errorf("stderr claims a written HTML report:\n%s", errs)
	}

	fresh := filepath.Join(dir, "new.html")
	_, _, errs = tuner(t, "scan", dead.URL, "--html", fresh, "--retries", "0")
	if _, err := os.Stat(fresh); err == nil {
		t.Error("an HTML page of failures was written")
	}
	if !strings.Contains(errs, "no HTML report written to "+fresh+": every target failed\n") {
		t.Errorf("stderr:\n%s", errs)
	}
}

func TestReportKeptOnCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sends SIGINT to the test process")
	}
	srv, started := hangingSite(t)
	path := writeOld(t)
	go func() {
		<-started
		interruptSelf() // execute catches it as a cancel
	}()
	code, _, errs := tuner(t, "scan", srv.URL, "-o", path, "--jsonl")
	if code != exitCanceled || !strings.Contains(errs, "no report written to "+path+": scan canceled; it keeps the previous report") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	assertOld(t, path)
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp")); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

// A canceled scan with no previous report writes the partial one, marked
// incomplete, so -o gets what stdout would.
func TestPartialReportOnCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sends SIGINT to the test process")
	}
	srv, started := hangingSite(t)
	path := filepath.Join(t.TempDir(), "report.json")
	go func() {
		<-started
		interruptSelf()
	}()
	code, _, errs := tuner(t, "scan", srv.URL, "-o", path, "--no-vulns")
	if code != exitCanceled {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"complete": false`) || !strings.Contains(string(data), `"stopped_by": "interrupted"`) {
		t.Errorf("partial report: %v\n%.400s", err, data)
	}
}

// -o through a symlink replaces the file it points to and keeps the link.
func TestReportThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	real := writeOld(t)
	link := filepath.Join(t.TempDir(), "latest.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", link, "-q"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v, %v", fi, err)
	}
	if data, _ := os.ReadFile(real); !strings.Contains(string(data), "leak-dotenv") {
		t.Errorf("target not written:\n%.200s", data)
	}

	// A dangling link, relative to its folder: the report is created
	// where it points and the link stays.
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "out"), 0o755)
	dangling := filepath.Join(dir, "latest.json")
	if err := os.Symlink(filepath.Join("out", "first.json"), dangling); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", dangling, "-q"); code != exitOK {
		t.Fatalf("dangling: exit %d: %s", code, errs)
	}
	if fi, err := os.Lstat(dangling); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the dangling link was replaced: %v, %v", fi, err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "out", "first.json")); !strings.Contains(string(data), "leak-dotenv") {
		t.Errorf("dangling target not written:\n%.200s", data)
	}
}

// A temporary report left by a killed run is removed once it is a day
// old; a fresh one may belong to a scan still running.
func TestStaleTemporaryReportsRemoved(t *testing.T) {
	path := writeOld(t)
	dir := filepath.Dir(path)
	stale, fresh := filepath.Join(dir, ".report.json.111.tmp"), filepath.Join(dir, ".report.json.222.tmp")
	for _, n := range []string{stale, fresh} {
		os.WriteFile(n, []byte("{"), 0o600)
	}
	old := time.Now().Add(-25 * time.Hour)
	os.Chtimes(stale, old, old)
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", path, "-q"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale file kept: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh file removed: %v", err)
	}
}

// TestHelperProcess runs the CLI in a child process for tests that kill it.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("TUNER_HELPER_ARGS") == "" {
		t.Skip("only runs as a child process")
	}
	stderr := io.Discard
	if os.Getenv("TUNER_HELPER_STDERR") != "" {
		stderr = os.Stderr
	}
	if os.Getenv("TUNER_HELPER_HANG") != "" {
		// A target stuck where cancellation can't reach it, like a read
		// from a FIFO.
		scanOne = func(*scanPlan, context.Context, *engine.Scanner, string, engine.Hooks) (*engine.Result, error) {
			fmt.Fprintln(os.Stderr, "scan blocked")
			time.Sleep(time.Hour)
			return nil, nil
		}
	}
	os.Exit(run(strings.Split(os.Getenv("TUNER_HELPER_ARGS"), "\n"), io.Discard, stderr))
}

func TestSecondInterruptQuits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sends SIGINT to a child process")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(),
		"TUNER_HELPER_ARGS="+strings.Join([]string{"scan", t.TempDir(), "--no-vulns", "--no-check-updates"}, "\n"),
		"TUNER_HELPER_HANG=1", "TUNER_HELPER_STDERR=1", "RHYTHM_OFFLINE=1",
		"XDG_CONFIG_HOME="+t.TempDir(), "XDG_CACHE_HOME="+t.TempDir())
	pipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	waitFor := func(want string) {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("the child exited before printing %q", want)
				}
				if strings.Contains(line, want) {
					return
				}
			case <-deadline:
				t.Fatalf("no %q from the child", want)
			}
		}
	}

	waitFor("scan blocked")
	cmd.Process.Signal(os.Interrupt)
	waitFor("rhythm tuner scan: stopping... press Ctrl+C again to quit now")
	cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() {
		for range lines { // drain, so the child never blocks on a full pipe
		}
		done <- cmd.Wait()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the second Ctrl+C did not end the scan within 1s")
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Errorf("want the child ended by SIGINT, got %v", cmd.ProcessState)
	}
}

func TestPanicInOneTarget(t *testing.T) {
	good, bad := leakySite(t), cleanSite(t)
	orig := scanOne
	defer func() { scanOne = orig }()
	scanOne = func(p *scanPlan, ctx context.Context, s *engine.Scanner, target string, h engine.Hooks) (*engine.Result, error) {
		if target == bad.URL {
			panic("boom")
		}
		return orig(p, ctx, s, target, h)
	}
	code, out, errs := tuner(t, "scan", good.URL, bad.URL, "--json", "--no-vulns")
	var reps []struct{ Target, Error string }
	if err := json.Unmarshal([]byte(out), &reps); err != nil || len(reps) != 2 || reps[0].Target != good.URL || reps[1].Error == "" {
		t.Fatalf("want the good target's report and an error entry: %v\n%s", err, out)
	}
	if code != exitError || !strings.Contains(errs, "rhythm tuner scan: "+bad.URL+": internal error (please report): boom") ||
		strings.Contains(errs, "goroutine ") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if _, _, errs := tuner(t, "scan", bad.URL, "--json", "--no-vulns", "-v"); !strings.Contains(errs, "goroutine ") {
		t.Errorf("-v should print the stack:\n%s", errs)
	}
}

func TestReportSurvivesSIGKILL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGKILL")
	}
	srv, started := hangingSite(t)
	path := writeOld(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(),
		"TUNER_HELPER_ARGS="+strings.Join([]string{"scan", srv.URL, "-o", path, "--rate", "0", "--no-vulns", "--no-check-updates"}, "\n"),
		"XDG_CONFIG_HOME="+t.TempDir(), "XDG_CACHE_HOME="+t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatal("the child never started scanning")
	}
	cmd.Process.Kill()
	cmd.Wait()
	assertOld(t, path) // a stray temporary file may stay behind; the report is intact
}

func TestReportFolderNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions that apply to this user")
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	dir := t.TempDir()
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	code, _, errs := tuner(t, "scan", srv.URL, "-o", filepath.Join(dir, "r.json"))
	if code != exitError || !strings.Contains(errs, "can't write the report to "+dir+": permission denied") || hits.Load() != 0 {
		t.Errorf("exit %d, %d requests, stderr %q", code, hits.Load(), errs)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--json", "-o", t.TempDir()); code != exitError || !strings.Contains(errs, "it is a directory") {
		t.Errorf("-o a directory: exit %d, stderr %q", code, errs)
	}
}

func TestTimeoutMessages(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(hang.Close)
	_, _, errs := tuner(t, "scan", hang.URL, "--timeout", "1s", "--retries", "0", "--no-vulns", "--plain")
	if !strings.Contains(errs, "no response within 1s (tried once)") || strings.Contains(errs, "--max-time;") {
		t.Errorf("--timeout: %q", errs)
	}
	_, _, errs = tuner(t, "scan", hang.URL, "--timeout", "5s", "--max-time", "300ms", "--no-vulns", "--plain")
	if !strings.Contains(errs, "stopped by --max-time; results are partial") {
		t.Errorf("--max-time: %q", errs)
	}
}

func TestReadTargets(t *testing.T) {
	got, err := readTargets(strings.NewReader("\uFEFFa.example\r\n# note\r\n\r\nb.example  # client\r\n"), "sites.txt")
	if err != nil || strings.Join(got, ",") != "a.example,b.example" {
		t.Errorf("BOM and CRLF: %q, %v", got, err)
	}
	for _, c := range []struct {
		line int
		long int
	}{{2, 70_000}, {3, 2 << 20}} {
		in := "a.example\n" + strings.Repeat("\n", c.line-2) + strings.Repeat("x", c.long) + "\nb.example\n"
		path := filepath.Join(t.TempDir(), "sites.txt")
		os.WriteFile(path, []byte(in), 0o600)
		code, _, errs := tuner(t, "scan", "-l", path, "--json")
		if want := fmt.Sprintf("%s line %d:", path, c.line); code != exitUsage || !strings.Contains(errs, want) {
			t.Errorf("%d-byte line: exit %d, stderr %.200q, want %q", c.long, code, errs, want)
		}
	}
}

func TestJSONLWriteError(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/full")
	}
	defer full.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("TUNER_CHECKS_URL", "http://127.0.0.1:1")
	var errb bytes.Buffer
	code := run([]string{"scan", leakySite(t).URL, "--jsonl", "--no-vulns", "--rate", "0"}, full, &errb)
	if code != exitError || !strings.Contains(errb.String(), "writing report:") {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
}

func TestBadHeaderValues(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, args := range [][]string{
		{"-H", "X-Test: a\r\nInjected: 1"},
		{"-H", "X-Test: a\nb"},
		{"-H", "X(Test): a"},
		{"-A", "tuner\r\nX-Injected: 1"},
		{"--cookie", "a=b\r\nX: y"},
	} {
		code, _, errs := tuner(t, append([]string{"scan", srv.URL}, args...)...)
		if code != exitUsage || !strings.Contains(errs, "bad ") {
			t.Errorf("%q: exit %d, stderr %q", args, code, errs)
		}
	}
	// A rejected header names the header but never shows its value: CI
	// logs keep what stderr says.
	for _, c := range []struct{ header, want string }{
		{"Authorization: Bearer topsecret\rX-Evil: 1", "rhythm tuner scan: bad -H Authorization: the value can't hold line breaks or control characters\n"},
		{"Bearer topsecret", "rhythm tuner scan: bad -H: use \"Name: value\"\n"},
	} {
		code, _, errs := tuner(t, "scan", srv.URL, "-H", c.header)
		if code != exitUsage || errs != c.want || strings.Contains(errs, "topsecret") {
			t.Errorf("%q: exit %d, stderr %q", c.header, code, errs)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("bad headers still sent %d requests", hits.Load())
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "-H", "X-Test: a\tb", "--no-vulns", "--json"); code != exitOK {
		t.Errorf("a tab is a valid header value: exit %d: %s", code, errs)
	}
}

func TestFlagErrorsAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "example.com", "--bogus"},
		{"scan", "example.com", "--rate", "fast"},
		{"scan", "example.com", "--timeout"},
	} {
		if code, _, _ := tuner(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

func TestOfflineSkipsUpdateCheck(t *testing.T) {
	var hits atomic.Int32
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"tag_name":"v9.0.0","assets":[]}`))
	}))
	defer gh.Close()
	t.Setenv("RHYTHM_GITHUB_API", gh.URL)
	t.Setenv("CI", "")
	t.Setenv("RHYTHM_NO_UPDATE_CHECK", "")
	old := version
	version = "0.1.0"
	defer func() { version = old }()

	site := cleanSite(t).URL
	if _, _, errs := tuner(t, "scan", site, "--plain", "--offline"); strings.Contains(errs, "new release") {
		t.Errorf("--offline printed an update notice:\n%s", errs)
	}
	t.Setenv("RHYTHM_OFFLINE", "1")
	if _, _, errs := tuner(t, "scan", site, "--plain"); strings.Contains(errs, "new release") {
		t.Errorf("RHYTHM_OFFLINE printed an update notice:\n%s", errs)
	}
	if hits.Load() != 0 {
		t.Errorf("offline runs asked GitHub %d times", hits.Load())
	}
	t.Setenv("RHYTHM_OFFLINE", "0")
	if _, _, errs := tuner(t, "scan", site, "--plain"); !strings.Contains(errs, "new release") {
		t.Errorf("RHYTHM_OFFLINE=0 should still check:\n%s", errs)
	}
}

func TestDuplicateTargetForms(t *testing.T) {
	var homes atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			homes.Add(1)
			w.Write([]byte("<html>home</html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	code, out, errs := tuner(t, "scan", host, srv.URL+"/", "HTTPS://"+strings.ToUpper(host), "-k", "--no-vulns", "--json")
	if code != exitOK || !strings.HasPrefix(strings.TrimSpace(out), "{") || homes.Load() != 1 {
		t.Errorf("exit %d, %d home requests, stderr %s\n%.100s", code, homes.Load(), errs, out)
	}

	for _, c := range [][2]string{
		{"example.com", "https://example.com/"},
		{"Example.COM", "https://example.com:443"},
		{"http://example.com:80/blog/", "http://example.com/blog"},
		{"[::1]:443", "https://[::1]"},
	} {
		if a, b := targetKey(c[0]), targetKey(c[1]); a != b {
			t.Errorf("%s and %s differ: %s, %s", c[0], c[1], a, b)
		}
	}
	for _, c := range [][2]string{
		{"example.com", "http://example.com"},
		{"example.com", "example.com/blog"},
		{"example.com:8443", "example.com"},
	} {
		if targetKey(c[0]) == targetKey(c[1]) {
			t.Errorf("%s and %s should stay apart", c[0], c[1])
		}
	}
}

// pluginSite looks like WordPress with contact-form-7 5.3.1, so a scan
// asks the vulnerability API about it.
func pluginSite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<link href="/wp-content/plugins/contact-form-7/s.css?ver=5.3.1">`))
		case "/wp-content/plugins/contact-form-7/readme.txt":
			w.Write([]byte("Stable tag: 5.3.1\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type statusReport struct {
	Complete  *bool  `json:"complete"`
	StoppedBy string `json:"stopped_by"`
	VulnData  string `json:"vuln_data"`
}

func TestFailOnNeedsVulnData(t *testing.T) {
	// The API accepts each connection and drops it without an answer.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
	}))
	defer api.Close()
	t.Setenv("TUNER_VULN_API", api.URL)
	t.Setenv("TUNER_WPORG_API", api.URL)
	t.Setenv("TUNER_PHPNET_API", api.URL)
	setCacheHome(t, t.TempDir())
	site := pluginSite(t).URL

	code, out, errs := tuner(t, "scan", site, "--json", "--fail-on", "high")
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if code != exitError || rep.VulnData != "missing" || rep.Complete == nil || !*rep.Complete ||
		!strings.Contains(errs, "no vulnerability data, so --fail-on high can't pass it") ||
		!strings.Contains(errs, "--allow-missing-vulns") {
		t.Errorf("exit %d, %+v, stderr %q", code, rep, errs)
	}
	if code, _, errs := tuner(t, "scan", site, "--json", "--fail-on", "high", "--allow-missing-vulns"); code != exitOK {
		t.Errorf("--allow-missing-vulns: exit %d: %s", code, errs)
	}
	if code, _, errs := tuner(t, "scan", site, "--json"); code != exitOK {
		t.Errorf("no --fail-on: exit %d: %s", code, errs)
	}
	code, out, _ = tuner(t, "scan", site, "--json", "--fail-on", "high", "--no-vulns")
	if json.Unmarshal([]byte(out), &rep); code != exitOK || rep.VulnData != "off" {
		t.Errorf("--no-vulns: exit %d, vuln_data %q", code, rep.VulnData)
	}
}

// --fail-on-new can't pass a scan with no vulnerability data either.
func TestFailOnNewNeedsVulnData(t *testing.T) {
	needScanFlags(t, "since", "fail-on-new")
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
	}))
	defer api.Close()
	t.Setenv("TUNER_VULN_API", api.URL)
	t.Setenv("TUNER_WPORG_API", api.URL)
	t.Setenv("TUNER_PHPNET_API", api.URL)
	setCacheHome(t, t.TempDir())
	site := pluginSite(t).URL
	before := filepath.Join(t.TempDir(), "before.json")
	if code, _, errs := tuner(t, "scan", site, "--no-vulns", "-o", before, "-q"); code != exitOK {
		t.Fatalf("before: exit %d: %s", code, errs)
	}

	code, _, errs := tuner(t, "scan", site, "--json", "--since", before, "--fail-on-new", "low")
	if code != exitError || !strings.Contains(errs, "no vulnerability data, so --fail-on-new low can't pass it") ||
		!strings.Contains(errs, "--allow-missing-vulns") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if code, _, errs := tuner(t, "scan", site, "--json", "--since", before, "--fail-on-new", "low", "--allow-missing-vulns"); code != exitOK {
		t.Errorf("--allow-missing-vulns: exit %d: %s", code, errs)
	}
}

func TestVulnDataOK(t *testing.T) {
	states, err := os.ReadFile("../../vulns/testdata/phpnet-states.json")
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/states.php" {
			w.Write(states)
			return
		}
		w.Write([]byte(`{"error":0,"data":{"vulnerability":[]}}`))
	}))
	defer api.Close()
	t.Setenv("TUNER_VULN_API", api.URL)
	t.Setenv("TUNER_WPORG_API", api.URL)
	t.Setenv("TUNER_PHPNET_API", api.URL)
	setCacheHome(t, t.TempDir())
	code, out, errs := tuner(t, "scan", pluginSite(t).URL, "--json", "--fail-on", "critical")
	var rep statusReport
	if json.Unmarshal([]byte(out), &rep); code != exitOK || rep.VulnData != "ok" {
		t.Errorf("exit %d, vuln_data %q, stderr %s\n%s", code, rep.VulnData, errs, out)
	}
}

func TestInterruptedReportSaysSo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sends SIGINT to the test process")
	}
	srv, started := hangingSite(t)
	go func() {
		<-started
		interruptSelf()
	}()
	code, out, errs := tuner(t, "scan", srv.URL, "--json", "--no-vulns")
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if code != exitCanceled || rep.Complete == nil || *rep.Complete || rep.StoppedBy != "interrupted" {
		t.Errorf("exit %d, %+v, stderr %q", code, rep, errs)
	}
}

func TestMaxTimeReportSaysSo(t *testing.T) {
	srv, _ := hangingSite(t)
	code, out, errs := tuner(t, "scan", srv.URL, "--json", "--no-vulns", "--max-time", "500ms", "--fail-on", "high")
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if code != exitError || *rep.Complete || rep.StoppedBy != "max-time" ||
		!strings.Contains(errs, "the scan is incomplete (stopped by --max-time)") {
		t.Errorf("exit %d, %+v, stderr %q", code, rep, errs)
	}
}

// The terminal view says a --max-time scan is incomplete above its score.
func TestMaxTimeViewSaysSo(t *testing.T) {
	srv, _ := hangingSite(t)
	_, out, errs := tuner(t, "scan", srv.URL, "--plain", "--no-vulns", "--max-time", "500ms")
	if !strings.Contains(out, "Incomplete: stopped by --max-time") {
		t.Errorf("no incomplete note, stderr %q\n%s", errs, out)
	}
}

func TestHTTPClientUsesProxy(t *testing.T) {
	var mu sync.Mutex
	var got struct{ url, ua string }
	seen := func() struct{ url, ua string } { mu.Lock(); defer mu.Unlock(); return got }
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got.url, got.ua = r.URL.String(), r.UserAgent() // a proxy sees the absolute URL
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	c := httpClient("rhythm-tuner/test", u, 5*time.Second)
	resp, err := c.Get("http://vulns.example.invalid/plugin/x/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if g := seen(); g.url != "http://vulns.example.invalid/plugin/x/" || g.ua != "rhythm-tuner/test" || c.Timeout != 5*time.Second {
		t.Errorf("proxy saw %+v, timeout %v", g, c.Timeout)
	}

	// A caller's own User-Agent wins and its request is left as it was.
	req, _ := http.NewRequest(http.MethodGet, "http://vulns.example.invalid/", nil)
	req.Header.Set("User-Agent", "custom")
	if resp, err := c.Do(req); err == nil {
		resp.Body.Close()
	}
	if g := seen(); g.ua != "custom" {
		t.Errorf("User-Agent %q, want custom", g.ua)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://vulns.example.invalid/", nil)
	if resp, err := c.Do(req); err == nil {
		resp.Body.Close()
	}
	if req.Header.Get("User-Agent") != "" {
		t.Error("the default User-Agent changed the caller's request")
	}

	// The check pack client goes through the same helper: proxy and
	// User-Agent.
	pc := packClient("rhythm-tuner/pack", u, false, false).HTTP
	if resp, err := pc.Get("http://checks.example.invalid/checks.tar.gz"); err == nil {
		resp.Body.Close()
	}
	if g := seen(); g.url != "http://checks.example.invalid/checks.tar.gz" || g.ua != "rhythm-tuner/pack" || pc.Timeout != 30*time.Second {
		t.Errorf("pack client: proxy saw %+v, timeout %v", g, pc.Timeout)
	}
}

// The help and README promise only what the code does today. Each claim
// listed here was too strong; the limits stay stated until the fix lands.
func TestHelpAndReadmeClaims(t *testing.T) {
	var help bytes.Buffer
	usage(&help)
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		text    string
		without []string
		with    []string
	}{
		"help": {help.String(),
			[]string{"refresh the check pack and vulnerability data now", "redirects to another host", "checksummed, not signed",
				"plugins with known\n                           advisories"},
			[]string{"-H and --cookie go only to the site you named,\n                           never to another host a redirect leads to",
				"signed with Ed25519", "Never runs\n                           site code", "--allow-missing-vulns", "--allow-partial"}},
		"README": {string(readme),
			[]string{"always masked", "which are [signed with cosign]", "Tuner is non-intrusive (plain GET requests",
				"Tuner sends ordinary, rate-limited GET requests", "also after the home page redirects to another host",
				"Tuner does not yet refuse other methods", "The check pack is checksummed, not signed"},
			[]string{"Nothing checks the signature for you yet", "echo \"$HOME/.local/bin\" >> \"$GITHUB_PATH\""}},
	} {
		for _, s := range c.without {
			if strings.Contains(c.text, s) {
				t.Errorf("%s still says %q", name, s)
			}
		}
		for _, s := range c.with {
			if !strings.Contains(c.text, s) {
				t.Errorf("%s lacks %q", name, s)
			}
		}
	}
}

// TestMain names the binary "rhythm tuner" for every test, as the router
// does, so messages read the same however the test binary is called.
func TestMain(m *testing.M) {
	if os.Getenv(invokedAsEnv) == "" {
		os.Setenv(invokedAsEnv, "rhythm tuner")
	}
	// No test sends a DNS query; TestOwnNetworkRate fakes the names it needs.
	lookupIP = func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("no DNS in tests") }
	if os.Getenv(asTunerEnv) == "1" {
		// A child process a test started as the Tuner binary (watch runs
		// each scan as one).
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// asTunerEnv makes the test binary run as the Tuner binary, so watch's
// child scans can run in tests.
const asTunerEnv = "TUNER_TEST_AS_BINARY"

func TestCommandName(t *testing.T) {
	old := argv0
	defer func() { argv0 = old }()
	for _, c := range []struct{ env, argv0, want string }{
		{"", "/go/bin/rhythm-tuner", "rhythm-tuner"},
		{"", `C:\Users\me\go\bin\rhythm-tuner.EXE`, "rhythm-tuner"},
		{"", "./tuner", "tuner"},
		{"", "", "rhythm-tuner"},
		{"rhythm tuner", "/usr/local/bin/rhythm-tuner", "rhythm tuner"},
		{"rhythm t", "/usr/local/bin/rhythm-tuner", "rhythm t"},
		{"rhythm\x1b[2Jtuner", "/go/bin/rhythm-tuner", "rhythm-tuner"},
	} {
		t.Setenv(invokedAsEnv, c.env)
		argv0 = c.argv0
		if got := cmdName(); got != c.want {
			t.Errorf("env %q argv0 %q: %q, want %q", c.env, c.argv0, got, c.want)
		}
	}

	t.Setenv(invokedAsEnv, "")
	argv0 = "/go/bin/rhythm-tuner"
	_, out, _ := tuner(t, "--help")
	if !strings.Contains(out, "  rhythm-tuner scan <url>... [flags] scan one or more sites\n") ||
		!strings.Contains(out, "  rhythm-tuner scan example.com --profile quick") || strings.Contains(out, "rhythm tuner scan") {
		t.Errorf("go install name:\n%s", out)
	}
	_, _, errs := tuner(t, "scan")
	if !strings.Contains(errs, "try: rhythm-tuner scan example.com") {
		t.Errorf("hint: %s", errs)
	}

	t.Setenv(invokedAsEnv, "rhythm tuner")
	_, out, _ = tuner(t, "--help")
	if !strings.Contains(out, "  rhythm tuner scan <url>... [flags] scan one or more sites\n") || strings.Contains(out, "rhythm-tuner scan") {
		t.Errorf("router name:\n%s", out)
	}
	// With a long alias the descriptions keep their column: a command
	// too long for it gets a line of its own.
	t.Setenv(invokedAsEnv, "rhythm a-very-long-tool-name")
	_, out, _ = tuner(t, "--help")
	indent := strings.Repeat(" ", usageCmdWidth+3)
	if !strings.Contains(out, "  rhythm a-very-long-tool-name scan <url>... [flags]\n"+indent+"scan one or more sites\n") ||
		!strings.Contains(out, "\n"+indent+"and PHP vulnerability data now\n") {
		t.Errorf("long name:\n%s", out)
	}
}

// checks and update help line their summaries up in one column under any
// name, including a summary wrapped below a long command.
func TestSubcommandUsageColumns(t *testing.T) {
	old := argv0
	defer func() { argv0 = old }()
	argv0 = "/usr/local/bin/rhythm-tuner"
	for _, name := range []string{"rt", "rhythm tuner", ""} {
		t.Setenv(invokedAsEnv, name)
		for _, page := range [][]string{{"checks", "--help"}, {"update", "--help"}} {
			_, out, _ := tuner(t, page...)
			block, _, _ := strings.Cut(strings.TrimPrefix(out, "Usage:\n"), "\n\n")
			for _, summary := range []string{"write a new check", "write checks as Nuclei", "refresh everything", "cache what scans", "delete the cached"} {
				for line := range strings.Lines(block) {
					if i := strings.Index(line, summary); i >= 0 && i != usageCmdWidth+3 {
						t.Errorf("%q %v: %q starts at column %d, want %d:\n%s", name, page, summary, i, usageCmdWidth+3, block)
					}
				}
			}
		}
	}
}

// The users' N7 table: each mistake gets one line that says what to type,
// not the whole help. Each exits 2.
func TestFriendlyUsageErrors(t *testing.T) {
	t.Chdir(t.TempDir())
	os.Mkdir("wp", 0o755)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"scna", "./wp"}, "rhythm tuner: unknown command scna; did you mean scan?\n  run 'rhythm tuner --help' for the commands\n"},
		{[]string{"chekcs"}, "rhythm tuner: unknown command chekcs; did you mean checks?\n"},
		{[]string{"test-ecko"}, "rhythm tuner: unknown command test-ecko; did you mean test-echo?\n"},
		{[]string{"example.com"}, "rhythm tuner: unknown command example.com; to scan it, run: rhythm tuner scan example.com\n"},
		{[]string{"bogus"}, "rhythm tuner: unknown command bogus\n  run 'rhythm tuner --help' for the commands\n"},
		{[]string{"scan", "./wp", "--jsn"}, "rhythm tuner scan: unknown flag --jsn; did you mean --json?\n"},
		{[]string{"scan", "./wp", "-Q"}, "rhythm tuner scan: unknown flag -Q; did you mean -q?\n"},
		{[]string{"scan", "./wp", "--zzzzzz"}, "rhythm tuner scan: unknown flag --zzzzzz\n"},
		{[]string{"scan", "./wp", "--no-check-updates", "--id", "leak-dotnev"}, "rhythm tuner scan: --id leak-dotnev: no check has this ID; did you mean leak-dotenv?\n  list them with: rhythm tuner checks\n"},
		{[]string{"scan", "./wp", "--fail-on", "urgent"}, "rhythm tuner scan: --fail-on urgent: want critical, high, medium, low or info\n"},
		{[]string{"scan", "./wp", "--fail-on", "hihg"}, "rhythm tuner scan: --fail-on hihg: want critical, high, medium, low or info; did you mean high?\n"},
		{[]string{"scan", "./wp", "--profile", "turbo"}, "rhythm tuner scan: --profile turbo: want quick or default\n"},
		{[]string{"scan", "./wp", "--timeout", "5"}, "rhythm tuner scan: --timeout 5: use a unit, for example 5s\n"},
		{[]string{"scan", "./wp", "--max-time", "soon"}, "rhythm tuner scan: --max-time soon: want a duration, for example 10s or 2m\n"},
		{[]string{"scan", "./wp", "--parallel", "0"}, "rhythm tuner scan: --parallel 0: want 1 or more\n"},
		{[]string{"scan", "./wp", "--rate", "-1"}, "rhythm tuner scan: --rate -1: want 0 or more (0 means no limit)\n"},
		{[]string{"scan", "./wp", "-c", "0"}, "rhythm tuner scan: --concurrency 0: want 1 or more\n"},
		{[]string{"scan", "./wp", "--retries", "x"}, "rhythm tuner scan: --retries x: want a whole number\n"},
		{[]string{"scan", "./wp", "--rate", "fast"}, "rhythm tuner scan: --rate fast: want a number\n"},
		{[]string{"scan", "./wp", "-o"}, "rhythm tuner scan: -o needs a value\n"},
		{[]string{"scan", "./wp", "--json=maybe"}, "rhythm tuner scan: --json=maybe: want true or false\n"},
		{[]string{"scan"}, "rhythm tuner scan: no target given\n  try: rhythm tuner scan example.com\n"},
	} {
		code, out, errs := tunerExact(t, c.args...)
		if code != exitUsage || !strings.HasPrefix(errs, c.want) || out != "" {
			t.Errorf("%v: exit %d\nstderr %q\nwant   %q\nstdout %.80q", c.args, code, errs, c.want, out)
		}
		if strings.Contains(errs, "Output:") {
			t.Errorf("%v: printed the help", c.args)
		}
	}
}

// Severities, profiles and confidence levels work in any case.
func TestValuesAnyCase(t *testing.T) {
	srv := leakySite(t)
	if code, _, errs := tuner(t, "scan", srv.URL, "--json", "--fail-on", "HIGH", "--profile", "Quick", "--severity", "Low", "--min-confidence", "Likely"); code != exitFindings {
		t.Errorf("exit %d: %s", code, errs)
	}
}

func TestScanHelp(t *testing.T) {
	code, out, _ := tuner(t, "scan", "--help")
	if code != exitOK || !strings.Contains(out, "  rhythm tuner scan <url>... [flags] scan one or more sites\n") ||
		!strings.Contains(out, "--fail-on <level>") || !strings.Contains(out, "Test extension:\n      --test-add <url>") ||
		!strings.Contains(out, "Exit codes:") {
		t.Errorf("scan --help: exit %d\n%s", code, out)
	}
	for _, other := range []string{"interactive picker", "rhythm tuner update [--clear]", "rhythm tuner checks [flags]", "test-echo"} {
		if strings.Contains(out, other) {
			t.Errorf("scan --help shows %q", other)
		}
	}
}

func TestJSONArray(t *testing.T) {
	srv := leakySite(t)
	code, out, errs := tuner(t, "scan", srv.URL, "--json-array")
	var reps []struct {
		Target   string
		Complete bool
	}
	if err := json.Unmarshal([]byte(out), &reps); code != exitOK || err != nil || len(reps) != 1 || reps[0].Target != srv.URL || !reps[0].Complete {
		t.Fatalf("exit %d, %v, stderr %s:\n%.300s", code, err, errs, out)
	}

	// With -o the extension decides nothing: --json-array is JSON.
	path := filepath.Join(t.TempDir(), "r.json")
	if code, _, errs := tuner(t, "scan", srv.URL, "--json-array", "-o", path, "-q"); code != exitOK {
		t.Fatalf("-o: exit %d: %s", code, errs)
	}
	if data, _ := os.ReadFile(path); !bytes.HasPrefix(data, []byte("[")) {
		t.Errorf("-o file is not an array:\n%.100s", data)
	}

	// A target that could not be scanned is an error entry.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	code, out, _ = tuner(t, "scan", dead.URL, "--json-array")
	var failed []struct{ Target, Error string }
	if err := json.Unmarshal([]byte(out), &failed); code != exitError || err != nil || len(failed) != 1 ||
		failed[0].Target != dead.URL || !strings.Contains(failed[0].Error, "can't reach") {
		t.Errorf("dead target: exit %d, %v:\n%s", code, err, out)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--json-array", "--md"); code != exitUsage || !strings.Contains(errs, "pick one output format") {
		t.Errorf("--json-array --md: exit %d: %s", code, errs)
	}
}

func TestSuggest(t *testing.T) {
	opts := []string{"scan", "checks", "update", "json", "jsonl", "q"}
	for word, want := range map[string]string{
		"scna": "scan", "sacn": "scan", "chceks": "checks", "updat": "update", "jsn": "json", "Json": "json",
		"x": "", "zzzz": "", "": "", "Q": "q",
	} {
		if got := suggest(word, opts); got != want {
			t.Errorf("suggest(%q) = %q, want %q", word, got, want)
		}
	}
	if d := editDistance("kitten", "sitting"); d != 3 {
		t.Errorf("editDistance = %d", d)
	}
}

// writeConfig puts a .tuner.yml in a fresh current folder.
func writeConfig(t *testing.T, body string) {
	t.Helper()
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".tuner.yml", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigFile(t *testing.T) {
	srv := leakySite(t)
	old := today
	defer func() { today = old }()
	today = func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) }

	// Targets and fail_on come from the file; the header says so.
	writeConfig(t, "targets: ["+srv.URL+"]\nfail_on: high\n")
	code, out, errs := tuner(t, "scan", "--plain")
	if code != exitFindings || !strings.Contains(out, "scanning "+srv.URL+" (config: .tuner.yml)") || !strings.Contains(out, ".env file exposed") {
		t.Fatalf("fail_on from config: exit %d, stderr %s\n%s", code, errs, out)
	}

	// An ignore hides the finding and the score says ignores, not baseline.
	writeConfig(t, "targets: ["+srv.URL+"]\nfail_on: high\nignore:\n  - id: leak-dotenv\n    path: /.env\n    reason: demo keys\n    until: 2026-10-24\n")
	code, out, errs = tuner(t, "scan", "--plain")
	if code != exitOK || strings.Contains(out, ".env file exposed") || !strings.Contains(out, "after ignores (1 hidden)") {
		t.Errorf("ignored: exit %d, stderr %s\n%s", code, errs, out)
	}
	code, out, _ = tuner(t, "scan", "--json")
	if code != exitOK || strings.Contains(out, "leak-dotenv") {
		t.Errorf("ignored JSON: exit %d\n%s", code, out)
	}
	code, out, _ = tuner(t, "scan", "--jsonl")
	if code != exitOK || strings.Contains(out, "leak-dotenv") {
		t.Errorf("ignored JSONL: exit %d\n%s", code, out)
	}

	// Flags win: --fail-on medium fails on the missing headers. A target
	// on the command line replaces the file's.
	if code, _, errs := tuner(t, "scan", "--json", "--fail-on", "medium"); code != exitFindings {
		t.Errorf("--fail-on over config: exit %d: %s", code, errs)
	}
	clean := cleanSite(t)
	if code, out, _ := tuner(t, "scan", clean.URL, "--json"); code != exitOK || strings.Contains(out, srv.URL) {
		t.Errorf("command line target: exit %d\n%.200s", code, out)
	}
	// --no-config reads nothing, so there is no target.
	if code, _, errs := tuner(t, "scan", "--no-config"); code != exitUsage || !strings.Contains(errs, "no target given") {
		t.Errorf("--no-config: exit %d: %s", code, errs)
	}

	// Under -q and machine output stderr still names the file and the
	// targets it chose; a target on the command line is not the file's.
	code, _, errs = tuner(t, "scan", "-q", "--json")
	if want := "rhythm tuner scan: using .tuner.yml, which chose the target: " + srv.URL + "\n"; code != exitOK || !strings.Contains(errs, want) {
		t.Errorf("config note: exit %d, stderr %q, want %q", code, errs, want)
	}
	if _, _, errs := tuner(t, "scan", clean.URL, "-q", "--json"); !strings.Contains(errs, "rhythm tuner scan: using .tuner.yml\n") {
		t.Errorf("config note with a command line target: %q", errs)
	}

	// The day after until, the ignore stops hiding and says so.
	today = func() time.Time { return time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC) }
	code, out, errs = tuner(t, "scan", "--plain", "-q")
	if code != exitFindings || !strings.Contains(out, ".env file exposed") ||
		!strings.Contains(errs, "rhythm tuner scan: ignore for leak-dotenv /.env expired 2026-10-24: demo keys\n") {
		t.Errorf("expired: exit %d, stderr %s\n%s", code, errs, out)
	}
}

func TestConfigHeadersAndErrors(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			got.Store(r.Header.Get("Authorization") + "|" + r.Header.Get("X-Team"))
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	writeConfig(t, "headers:\n  Authorization: Bearer ${TUNER_TEST_TOKEN}\n  X-Team: web\n")
	t.Setenv("TUNER_TEST_TOKEN", "tok-123")
	if code, _, errs := tuner(t, "scan", srv.URL, "--json", "--no-vulns", "-H", "X-Team: ops"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if v, _ := got.Load().(string); v != "Bearer tok-123|ops" {
		t.Errorf("headers sent: %q (want the config's Authorization and -H's X-Team)", v)
	}

	t.Setenv("TUNER_TEST_TOKEN", "")
	code, out, errs := tuner(t, "scan", srv.URL)
	if code != exitUsage || errs != "rhythm tuner scan: .tuner.yml: headers: Authorization uses ${TUNER_TEST_TOKEN}, which is not set\n" || out != "" {
		t.Errorf("missing variable: exit %d, stderr %q", code, errs)
	}

	// A .tuner.yml from an untrusted repository can't copy a variable set
	// for something else into a request, even to a host it picked.
	writeConfig(t, "targets: ["+srv.URL+"]\nheaders:\n  X-Leak: ${SECRET_TOKEN}\n")
	t.Setenv("SECRET_TOKEN", "ci-secret-value")
	got.Store("")
	code, out, errs = tuner(t, "scan", "-q", "--json")
	if code != exitUsage || out != "" || strings.Contains(errs, "ci-secret-value") ||
		!strings.Contains(errs, "X-Leak uses ${SECRET_TOKEN}; only variables that start with TUNER_ can be used") {
		t.Errorf("untrusted variable: exit %d, stderr %q", code, errs)
	}
	if v, _ := got.Load().(string); v != "" {
		t.Errorf("a request was sent: %q", v)
	}

	writeConfig(t, "fail_on: high\nprofle: quick\n")
	if code, _, errs := tuner(t, "scan", srv.URL); code != exitUsage || !strings.Contains(errs, `.tuner.yml line 2: unknown key "profle"`) {
		t.Errorf("unknown key: exit %d: %s", code, errs)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--config", "nope.yml"); code != exitUsage || !strings.Contains(errs, "--config nope.yml: no such file") {
		t.Errorf("missing --config: exit %d: %s", code, errs)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--config", "x.yml", "--no-config"); code != exitUsage || !strings.Contains(errs, "don't go together") {
		t.Errorf("--config with --no-config: exit %d: %s", code, errs)
	}

	// --config names another file; its baseline and folders are relative
	// to that file.
	os.MkdirAll("ci/site", 0o755)
	os.WriteFile("ci/site/.env", []byte("DB_PASSWORD="+rawSecret+"\n"), 0o600)
	os.WriteFile("ci/tuner.yml", []byte("targets: [./site]\nfail_on: high\n"), 0o600)
	code, out, errs = tuner(t, "scan", "--config", "ci/tuner.yml", "--plain", "--no-vulns")
	if code != exitFindings || !strings.Contains(out, "(config: ci/tuner.yml)") || !strings.Contains(out, ".env file in the web root") {
		t.Errorf("--config: exit %d, stderr %s\n%s", code, errs, out)
	}
}

// A .tuner.yml from a pull request can choose the targets, so -H and
// --cookie from the command line (often CI secrets) are refused unless
// the command line names the targets too. The config's own headers still
// go to the hosts it chose.
func TestConfigTargetsGetNoCommandLineCredentials(t *testing.T) {
	var hits atomic.Int32
	var leaked atomic.Value
	leaked.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if v := r.Header.Get("Authorization") + r.Header.Get("Cookie"); v != "" {
			leaked.Store(v)
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	writeConfig(t, "targets: ["+srv.URL+"]\n")
	want := "rhythm tuner scan: -H and --cookie need targets on the command line when .tuner.yml chooses them: name the targets or use --no-config\n"
	for _, args := range [][]string{
		{"-H", "Authorization: Bearer s3cret"},
		{"--header", "Authorization: Bearer s3cret"},
		{"--cookie", "sess=abc"},
	} {
		code, out, errs := tuner(t, append([]string{"scan", "-q", "--json"}, args...)...)
		if code != exitUsage || out != "" || errs != want || strings.Contains(errs, "s3cret") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out, errs)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d requests reached the config's target", n)
	}

	// Named on the command line, the target gets them.
	if code, _, errs := tuner(t, "scan", srv.URL, "-q", "--json", "--no-vulns", "-H", "Authorization: Bearer s3cret"); code != exitOK {
		t.Fatalf("command line target: exit %d: %s", code, errs)
	}
	if v, _ := leaked.Load().(string); v != "Bearer s3cret" {
		t.Errorf("command line target got %q", v)
	}

	// A header that reads a TUNER_ variable is a secret too: it goes
	// only to targets the command line named.
	leaked.Store("")
	before := hits.Load()
	writeConfig(t, "targets: ["+srv.URL+"]\nheaders:\n  Cookie: ${TUNER_TEST_COOKIE}\n")
	t.Setenv("TUNER_TEST_COOKIE", "from-config-s3cr3t")
	code, out, errs := tuner(t, "scan", "-q", "--json", "--no-vulns")
	want = "rhythm tuner scan: .tuner.yml chooses the targets, so its headers can't read ${TUNER_...} variables (Cookie): name the targets on the command line or use --no-config\n"
	if code != exitUsage || out != "" || errs != want || strings.Contains(errs, "s3cr3t") {
		t.Errorf("config env header: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if hits.Load() != before {
		t.Errorf("the config's own target got requests")
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "-q", "--json", "--no-vulns"); code != exitOK {
		t.Fatalf("config headers, target on the command line: exit %d: %s", code, errs)
	}
	if v, _ := leaked.Load().(string); v != "from-config-s3cr3t" {
		t.Errorf("config header sent as %q", v)
	}

	// A header written out in the file holds nothing secret and still
	// goes to the targets it chose.
	leaked.Store("")
	writeConfig(t, "targets: ["+srv.URL+"]\nheaders:\n  Cookie: plain=1\n")
	if code, _, errs := tuner(t, "scan", "-q", "--json", "--no-vulns"); code != exitOK {
		t.Fatalf("config literal header: exit %d: %s", code, errs)
	}
	if v, _ := leaked.Load().(string); v != "plain=1" {
		t.Errorf("config header sent as %q", v)
	}
}

// A .tuner.yml found in the current folder can't send a scan outside its
// folder. The request limits it sets are named even under -q.
func TestConfigStaysInItsFolder(t *testing.T) {
	writeConfig(t, "targets: [../site]\n")
	code, _, errs := tuner(t, "scan", "-q", "--no-vulns")
	if want := "rhythm tuner scan: .tuner.yml: targets: ../site is outside the folder that holds .tuner.yml; name it on the command line or pass --config\n"; code != exitUsage || errs != want {
		t.Errorf("../ target: exit %d, stderr %q", code, errs)
	}
	for _, body := range []string{"targets: [/etc]\n", "targets: [sub/../../x]\n"} {
		writeConfig(t, body)
		if code, _, errs := tuner(t, "scan", "-q", "--no-vulns"); code != exitUsage || !strings.Contains(errs, "is outside the folder") {
			t.Errorf("%q: exit %d, stderr %q", body, code, errs)
		}
	}
	writeConfig(t, "baseline: ../old.json\n")
	if code, _, errs := tuner(t, "scan", "./x", "-q", "--no-vulns"); code != exitUsage || !strings.Contains(errs, "baseline: ../old.json is outside the folder") {
		t.Errorf("../ baseline: exit %d, stderr %q", code, errs)
	}
	// Named with --config, the file is the user's choice.
	writeConfig(t, "targets: [../site]\n")
	if code, _, errs := tuner(t, "scan", "--config", ".tuner.yml", "-q", "--no-vulns"); strings.Contains(errs, "outside the folder") {
		t.Errorf("--config: exit %d, stderr %q", code, errs)
	}

	srv := leakySite(t)
	writeConfig(t, "targets: ["+srv.URL+"]\nrate: 0\nconcurrency: 500\n")
	_, _, errs = tunerExact(t, "scan", "-q", "--no-vulns", "--json")
	if want := "using .tuner.yml, which chose the target: " + srv.URL + "; it sets --rate 0 (no limit) and --concurrency 500\n"; !strings.Contains(errs, want) {
		t.Errorf("limits note: stderr %q", errs)
	}
}

// The ignore entries and baseline a .tuner.yml brings are counted on
// stderr even under -q and machine output: an untrusted file could hide
// every finding from --fail-on.
func TestConfigHiddenFindingsNote(t *testing.T) {
	srv := leakySite(t)
	writeConfig(t, "ignore:\n  - id: \"*\"\n    reason: x\n  - id: nothing-matches\n    reason: y\n")
	code, _, errs := tuner(t, "scan", srv.URL, "-q", "--json", "--no-vulns", "--fail-on", "low")
	if want := "rhythm tuner scan: .tuner.yml: 2 ignore entries hid "; code != exitOK || !strings.Contains(errs, want) || strings.Contains(errs, "hid 0 findings") {
		t.Errorf("ignore note: exit %d, stderr %q", code, errs)
	}

	// A baseline named in the file is counted too; one from --baseline is
	// the caller's own choice and needs no note.
	_, out, _ := tuner(t, "scan", srv.URL, "-q", "--json", "--no-vulns", "--no-config")
	if err := os.WriteFile("base.json", []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(".tuner.yml", []byte("baseline: base.json\n"), 0o600)
	code, _, errs = tuner(t, "scan", srv.URL, "-q", "--json", "--no-vulns", "--fail-on", "low")
	if code != exitOK || !regexp.MustCompile(`rhythm tuner scan: \.tuner\.yml: the baseline \S*base\.json hid [1-9]\d* findings?\n`).MatchString(errs) {
		t.Errorf("baseline note: exit %d, stderr %q", code, errs)
	}
	os.WriteFile(".tuner.yml", []byte("fail_on: low\n"), 0o600)
	if _, _, errs := tuner(t, "scan", srv.URL, "-q", "--json", "--no-vulns", "--baseline", "base.json"); strings.Contains(errs, " hid ") {
		t.Errorf("note without config ignores: %q", errs)
	}
}

// A file -l or --config can't open is a usage error that says why.
func TestUnreadableListAndConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	if code, _, errs := tuner(t, "scan", "-l", "nope.txt"); code != exitUsage || errs != "rhythm tuner scan: -l nope.txt: no such file or directory\n" {
		t.Errorf("-l: exit %d: %q", code, errs)
	}
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return // permissions don't stop root
	}
	os.Mkdir("locked", 0o700)
	os.WriteFile("locked/tuner.yml", []byte("fail_on: high\n"), 0o600)
	os.Chmod("locked", 0)
	defer os.Chmod("locked", 0o700)
	if code, _, errs := tuner(t, "scan", "x.example", "--config", "locked/tuner.yml"); code != exitUsage || errs != "rhythm tuner scan: --config locked/tuner.yml: permission denied\n" {
		t.Errorf("--config: exit %d: %q", code, errs)
	}
}

// U12: targets on the user's own machine or network get 50 requests a
// second unless --rate or the config sets one; public sites keep 5.
// A long target list resolves at most maxLookups names at once.
func TestOwnNetworkLookupsBounded(t *testing.T) {
	old := lookupIP
	defer func() { lookupIP = old }()
	var now, peak atomic.Int32
	lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		n := now.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		now.Add(-1)
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}, nil
	}
	var targets []string
	for i := range 100 {
		targets = append(targets, fmt.Sprintf("https://site%d.internal", i))
	}
	fast := ownNetworkTargets(targets, false)
	if len(fast) != len(targets) {
		t.Errorf("%d of %d targets on the own network", len(fast), len(targets))
	}
	if p := peak.Load(); p > maxLookups || p < 2 {
		t.Errorf("peak of %d lookups at once, want 2 to %d", p, maxLookups)
	}
}

func TestOwnNetworkRate(t *testing.T) {
	old := lookupIP
	defer func() { lookupIP = old }()
	lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		ips := map[string][]string{
			"staging.internal": {"192.168.1.20", "fd00::20"},
			"example.com":      {"93.184.215.14"},
			"split.example":    {"10.0.0.9", "93.184.215.14"},
		}[host]
		if ips == nil {
			return nil, errors.New("no such host")
		}
		var out []net.IPAddr
		for _, ip := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
		}
		return out, nil
	}
	t.Chdir(t.TempDir())
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	for _, c := range []struct {
		target string
		extra  []string
		want   float64
	}{
		{"127.0.0.1", nil, 50},
		{"http://127.0.0.1:8080", nil, 50},
		{"10.0.0.5", nil, 50},
		{"[::1]", nil, 50},
		{"http://[fe80::1%25eth0]:8080", nil, 50},
		{"169.254.10.1", nil, 50},
		{"localhost:8080", nil, 50},
		{"app.localhost", nil, 50},
		{"staging.internal", nil, 50},
		{"example.com", nil, 5},
		{"split.example", nil, 5}, // one public address is enough to stay polite
		{"unresolvable.example", nil, 5},
		{"8.8.8.8", nil, 5},
		{"127.0.0.1", []string{"--rate", "5"}, 5},
		{"127.0.0.1", []string{"--rate", "0"}, 0},
		{"staging.internal", []string{"--proxy", "http://127.0.0.1:20221"}, 5}, // the proxy resolves it
		{"127.0.0.1", []string{"--proxy", "http://127.0.0.1:20221"}, 50},
	} {
		args := append([]string{c.target, "--no-vulns", "--no-check-updates", "--no-config"}, c.extra...)
		p, err := planScan(args, nil)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got := p.rateFor(c.target); got != c.want {
			t.Errorf("%v: rate %g, want %g", args, got, c.want)
		}
	}

	// A rate in .tuner.yml counts as given.
	writeConfig(t, "rate: 3\n")
	p, err := planScan([]string{"127.0.0.1", "--no-vulns", "--no-check-updates"}, nil)
	if err != nil || p.rateFor("127.0.0.1") != 3 {
		t.Errorf("config rate: %v", err)
	}
}

// The header says when the automatic rate applies. A scan of a local
// test server without --rate gets it.
func TestOwnNetworkRateHeader(t *testing.T) {
	srv := leakySite(t)
	t.Chdir(t.TempDir())
	code, out, errs := tunerExact(t, "scan", srv.URL, "--plain", "--no-config")
	if code != exitOK || !strings.Contains(out, "scanning "+srv.URL+" (local address: 50 req/s)") {
		t.Errorf("exit %d, stderr %s\n%s", code, errs, out)
	}
	_, out, _ = tunerExact(t, "scan", srv.URL, "--plain", "--no-config", "--rate", "100")
	if strings.Contains(out, "req/s") {
		t.Errorf("--rate given, header still names the automatic rate:\n%s", out)
	}
}

// U12: deep is hidden from help and the picker but still accepted, with a
// note that it matches default.
func TestDeepProfileHidden(t *testing.T) {
	var help bytes.Buffer
	usage(&help)
	scanUsage(&help)
	// --plugins names its own deep mode; only the profile is hidden.
	for _, line := range strings.Split(help.String(), "\n") {
		if strings.Contains(line, "--profile") && strings.Contains(line, "deep") {
			t.Errorf("help still offers --profile deep: %s", line)
		}
	}
	srv := leakySite(t)
	code, _, errs := tuner(t, "scan", srv.URL, "--json", "--profile", "Deep")
	if code != exitOK || !strings.Contains(errs, "rhythm tuner scan: --profile deep: no check uses it yet, so it runs the same checks as default\n") {
		t.Errorf("--profile deep: exit %d\n%s", code, errs)
	}
	if _, _, errs := tuner(t, "scan", srv.URL, "--json", "--profile", "default"); strings.Contains(errs, "deep") {
		t.Errorf("--profile default mentions deep:\n%s", errs)
	}
	if _, _, errs := tuner(t, "scan", srv.URL, "--json", "--profile", "deep", "-q"); strings.Contains(errs, "deep") {
		t.Errorf("-q still prints the deep note:\n%s", errs)
	}
}

// needCommand skips a test until another lane's command is registered in
// this binary, so the end-to-end tests below run on the integration
// branch with no edit here.
func needCommand(t *testing.T, name string) {
	t.Helper()
	if lookupCommand(name) == nil {
		t.Skipf("rhythm tuner %s is not registered in this build", name)
	}
}

// needScanFlags skips a test until a scan extension registers the flags.
func needScanFlags(t *testing.T, names ...string) {
	t.Helper()
	var o scanOptions
	fs := scanFlagSet(&o, io.Discard)
	for _, e := range scanExtensions {
		e.Flags(fs)
	}
	for _, n := range names {
		if fs.Lookup(n) == nil {
			t.Skipf("scan --%s is not registered in this build", n)
		}
	}
}

// laneReports writes two JSON reports of one site: before.json without
// the exposed .env and after.json with it. The leak is new in after.
func laneReports(t *testing.T) (srv *httptest.Server, before, after string) {
	t.Helper()
	srv = leakySite(t)
	dir := t.TempDir()
	before, after = filepath.Join(dir, "before.json"), filepath.Join(dir, "after.json")
	if code, _, errs := tuner(t, "scan", srv.URL, "--no-vulns", "--exclude-id", "leak-dotenv", "-o", before, "-q"); code != exitOK {
		t.Fatalf("before: exit %d: %s", code, errs)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--no-vulns", "-o", after, "-q"); code != exitOK {
		t.Fatalf("after: exit %d: %s", code, errs)
	}
	return srv, before, after
}

func TestEndToEndDiff(t *testing.T) {
	needCommand(t, "diff")
	_, before, after := laneReports(t)
	code, out, errs := tuner(t, "diff", before, after, "--fail-on-new", "high")
	if code != exitFindings || !strings.Contains(out, "1 new, 0 fixed") || !strings.Contains(out, ".env file exposed") {
		t.Errorf("new leak: exit %d, stderr %s\n%s", code, errs, out)
	}
	if code, out, errs := tuner(t, "diff", after, before, "--fail-on-new", "high"); code != exitOK {
		t.Errorf("leak fixed: exit %d, stderr %s\n%s", code, errs, out)
	}
	if code, _, _ := tuner(t, "diff", before); code != exitUsage {
		t.Errorf("one report: exit %d, want %d", code, exitUsage)
	}
}

func TestEndToEndReportHTML(t *testing.T) {
	needCommand(t, "report")
	_, before, after := laneReports(t)
	html := filepath.Join(t.TempDir(), "client.html")
	code, _, errs := tuner(t, "report", after, "--since", before, "--brand-name", "Acme Web", "-o", html)
	body, _ := os.ReadFile(html)
	if code != exitOK || !strings.Contains(strings.ToLower(string(body)), "<!doctype html") ||
		!strings.Contains(string(body), "Acme Web") || strings.Contains(string(body), rawSecret) {
		t.Errorf("report --html: exit %d, stderr %s, %d bytes", code, errs, len(body))
	}
	if code, _, _ := tuner(t, "report", filepath.Join(t.TempDir(), "missing.json"), "--html"); code == exitOK {
		t.Error("a missing report should fail")
	}

	// scan --html writes the same kind of file next to the scan.
	needScanFlags(t, "html")
	srv := leakySite(t)
	html = filepath.Join(t.TempDir(), "scan.html")
	if code, _, errs := tuner(t, "scan", srv.URL, "--no-vulns", "--html", html, "-q"); code != exitOK {
		t.Errorf("scan --html: exit %d: %s", code, errs)
	} else if body, _ := os.ReadFile(html); !strings.Contains(string(body), ".env") {
		t.Errorf("scan --html lacks the finding:\n%.300s", body)
	}
}

func TestEndToEndFix(t *testing.T) {
	needCommand(t, "fix")
	_, _, after := laneReports(t)
	for _, server := range []string{"nginx", "apache"} {
		code, out, errs := tuner(t, "fix", after, "--server", server)
		if code != exitOK || strings.TrimSpace(out) == "" {
			t.Errorf("fix --server %s: exit %d, stderr %s\n%s", server, code, errs, out)
		}
	}
	if code, _, _ := tuner(t, "fix", after, "--server", "iis"); code != exitUsage {
		t.Errorf("fix --server iis: exit %d, want %d", code, exitUsage)
	}
}

func TestEndToEndExplain(t *testing.T) {
	needCommand(t, "explain")
	code, out, errs := tuner(t, "explain", "leak-dotenv", "--no-check-updates")
	if code != exitOK || !strings.Contains(out, "leak-dotenv") {
		t.Errorf("explain leak-dotenv: exit %d, stderr %s\n%s", code, errs, out)
	}
	code, out, _ = tuner(t, "explain", "leak-dotenv", "--no-check-updates", "--json")
	var e struct{ ID, Kind string }
	if code != exitOK || json.Unmarshal([]byte(out), &e) != nil || e.ID != "leak-dotenv" || e.Kind != "check" {
		t.Errorf("explain --json: exit %d, %+v\n%s", code, e, out)
	}
	if code, _, _ := tuner(t, "explain", "no-such-check", "--no-check-updates"); code == exitOK {
		t.Error("explain of an unknown ID should fail")
	}
}

// wordPressFolder makes a folder that reads as a WordPress install.
func wordPressFolder(t *testing.T, dir string) {
	t.Helper()
	for name, body := range map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.4.1';\n",
		"wp-config.php":           "<?php\ndefine('DB_NAME', 'wp');\n",
		"wp-login.php":            "<?php\n",
		"index.php":               "<?php\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEndToEndIntegrityAndDiscover(t *testing.T) {
	needScanFlags(t, "integrity", "discover")
	root := t.TempDir()
	wordPressFolder(t, filepath.Join(root, "shop"))
	wordPressFolder(t, filepath.Join(root, "blog"))

	// The checksum service is down in tests, so --integrity can only say so;
	// it must not crash or fail the scan.
	code, out, errs := tuner(t, "scan", filepath.Join(root, "shop"), "--integrity", "--offline", "--plain")
	if code != exitOK && code != exitFindings {
		t.Errorf("--integrity: exit %d, stderr %s\n%s", code, errs, out)
	}

	code, out, errs = tuner(t, "scan", root, "--discover", "--offline", "--json")
	var reps []struct{ Target string }
	if (code != exitOK && code != exitFindings) || json.Unmarshal([]byte(out), &reps) != nil || len(reps) != 2 {
		t.Errorf("--discover: exit %d, %d reports, stderr %s\n%.400s", code, len(reps), errs, out)
	}
}

// --integrity with the checksum service down compared no file, so a
// --fail-on gate must not pass it, the same as missing vulnerability
// data, unless --allow-partial accepts that.
func TestEndToEndIntegrityChecksumsDown(t *testing.T) {
	needScanFlags(t, "integrity")
	setCacheHome(t, t.TempDir())
	site := filepath.Join(t.TempDir(), "shop")
	wordPressFolder(t, site)

	code, out, errs := tuner(t, "scan", site, "--integrity", "--no-vulns", "--json", "--fail-on", "high")
	var rep struct {
		Complete  bool   `json:"complete"`
		StoppedBy string `json:"stopped_by"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("report: %v\n%s", err, out)
	}
	if code != exitError || rep.Complete || rep.StoppedBy != "integrity" {
		t.Errorf("exit %d, complete %v, stopped by %q; want 3, false, integrity\n%s", code, rep.Complete, rep.StoppedBy, errs)
	}
	if !strings.Contains(errs, "the scan is incomplete (some checksums for --integrity could not be loaded), so --fail-on high can't pass it") {
		t.Errorf("stderr lacks the reason:\n%s", errs)
	}

	code, _, errs = tuner(t, "scan", site, "--integrity", "--no-vulns", "--json", "--fail-on", "high", "--allow-partial")
	if code != exitOK && code != exitFindings {
		t.Errorf("--allow-partial: exit %d\n%s", code, errs)
	}
}

func TestEndToEndPluginsDeep(t *testing.T) {
	needScanFlags(t, "plugins", "request-budget")
	srv := leakySite(t)
	code, out, errs := tuner(t, "scan", srv.URL, "--no-vulns", "--plugins", "deep", "--request-budget", "20", "--json")
	var rep struct{ Target string }
	if code != exitOK || json.Unmarshal([]byte(out), &rep) != nil || rep.Target == "" {
		t.Errorf("--plugins deep: exit %d, stderr %s\n%.300s", code, errs, out)
	}
	if code, _, _ := tuner(t, "scan", srv.URL, "--plugins", "turbo"); code != exitUsage {
		t.Errorf("--plugins turbo: exit %d, want %d", code, exitUsage)
	}
}

func TestEndToEndSinceAndNotify(t *testing.T) {
	needScanFlags(t, "since", "notify", "fail-on-new")
	srv, before, _ := laneReports(t)
	var mu sync.Mutex
	var posts []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		posts = append(posts, string(body))
		mu.Unlock()
	}))
	t.Cleanup(hook.Close)

	code, _, errs := tuner(t, "scan", srv.URL, "--no-vulns", "--since", before, "--fail-on-new", "high",
		"--notify", "webhook+"+hook.URL+"/hook", "-q")
	mu.Lock()
	defer mu.Unlock()
	if code != exitFindings || len(posts) != 1 || !strings.Contains(posts[0], "leak-dotenv") || strings.Contains(posts[0], rawSecret) {
		t.Errorf("--since --notify: exit %d, stderr %s, posts %q", code, errs, posts)
	}
	if code, _, _ := tuner(t, "scan", srv.URL, "--notify", "ftp://example.com"); code != exitUsage {
		t.Errorf("bad --notify: exit %d, want %d", code, exitUsage)
	}
}

// watch and serve run scans as child processes of the binary, which a
// test binary can't be, so only their command lines are tested here.
func TestEndToEndWatchAndServe(t *testing.T) {
	for _, c := range []struct{ name, want string }{{"watch", "--every"}, {"serve", "/v0/scans"}} {
		t.Run(c.name, func(t *testing.T) {
			needCommand(t, c.name)
			code, out, errs := tuner(t, c.name, "--help")
			if code != exitOK || !strings.Contains(out+errs, c.want) {
				t.Errorf("%s --help: exit %d\n%s%s", c.name, code, out, errs)
			}
			if code, _, _ := tuner(t, c.name, "--no-such-flag"); code != exitUsage {
				t.Errorf("%s --no-such-flag: exit %d, want %d", c.name, code, exitUsage)
			}
		})
	}
}

// A fresh watch with --fail-on-new and --notify runs its first scan (no
// earlier report) without failing, sends every finding, then fails and
// notifies on what is new in the next run.
func TestEndToEndWatchFirstRun(t *testing.T) {
	needCommand(t, "watch")
	srv := leakySite(t)
	list := filepath.Join(t.TempDir(), "sites.txt")
	if err := os.WriteFile(list, []byte(srv.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var posts []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		posts = append(posts, string(body))
		mu.Unlock()
	}))
	t.Cleanup(hook.Close)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(asTunerEnv, "1")
	var dir string
	watchOnce := func(scan ...string) (int, string, string) {
		args := append([]string{"watch", "-l", list, "--once", "--dir", dir, "--exec", exe,
			"--fail-on-new", "high", "--notify", "webhook+" + hook.URL + "/hook",
			"--", "--no-vulns", "--rate", "0", "--retries", "0"}, scan...)
		return tuner(t, args...)
	}
	logs := func() string {
		var b strings.Builder
		matches, _ := filepath.Glob(filepath.Join(dir, "*.log"))
		for _, m := range matches {
			data, _ := os.ReadFile(m)
			b.Write(data)
		}
		return b.String()
	}
	sent := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(posts)
	}

	// A fresh watch: every finding is sent, nothing fails the run.
	dir = filepath.Join(t.TempDir(), "fresh")
	code, out, errs := watchOnce()
	if got := sent(); code != exitOK || len(got) != 1 || !strings.Contains(got[0], "leak-dotenv") {
		t.Fatalf("fresh run: exit %d, posts %q\n%s%s\n%s", code, got, out, errs, logs())
	}

	// A second watch whose first run misses the leak: the next run finds
	// it new, fails and sends it.
	dir = filepath.Join(t.TempDir(), "second")
	if code, out, errs := watchOnce("--exclude-id", "leak-dotenv"); code != exitOK {
		t.Fatalf("first run: exit %d\n%s%s\n%s", code, out, errs, logs())
	}
	code, out, errs = watchOnce()
	if got := sent(); code != exitFindings || len(got) != 2 || !strings.Contains(got[1], "leak-dotenv") || !strings.Contains(out, "1 new") {
		t.Errorf("second run: exit %d, posts %d\n%s%s\n%s", code, len(got), out, errs, logs())
	}
}

func TestEndToEndInitCI(t *testing.T) {
	needCommand(t, "init")
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	code, _, errs := tuner(t, "init", "ci", "--target", "https://staging.example.com", "--sarif")
	body, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", "tuner.yml"))
	if code != exitOK || err != nil || !strings.Contains(string(body), "staging.example.com") {
		t.Fatalf("init ci: exit %d, stderr %s, %v\n%s", code, errs, err, body)
	}
	if code, _, _ := tuner(t, "init", "ci", "--target", "https://staging.example.com"); code == exitOK {
		t.Error("init ci replaced tuner.yml without --force")
	}
	if code, _, errs := tuner(t, "init", "ci", "--target", "https://staging.example.com", "--force"); code != exitOK {
		t.Errorf("init ci --force: exit %d: %s", code, errs)
	}
}

// Every command and the headline scan flags other lanes add need a row in
// the README's "You want to…" table once they are registered, so a merge
// that adds one without the row fails here.
func TestReadmeCoversLaneFeatures(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	table := string(readme)
	if i := strings.Index(table, "| You want to… | Run |"); i >= 0 {
		table = table[i:]
		if end := strings.Index(table, "\n\n"); end >= 0 {
			table = table[:end]
		}
	}
	for _, c := range commands {
		if strings.HasPrefix(c.Name, "test-") {
			continue // registered by tests only
		}
		want := "rhythm tuner " + c.Name
		if c.Name == "init" {
			want = "rhythm tuner init ci"
		}
		if !strings.Contains(table, want) {
			t.Errorf("the README task table has no row for %s", want)
		}
	}
	var o scanOptions
	fs := scanFlagSet(&o, io.Discard)
	for _, e := range scanExtensions {
		e.Flags(fs)
	}
	for flagName, want := range map[string]string{
		"html": "--html", "integrity": "--integrity", "discover": "--discover",
		"plugins": "--plugins deep", "since": "--since", "notify": "--notify",
	} {
		if fs.Lookup(flagName) != nil && !strings.Contains(table, want) {
			t.Errorf("the README task table has no row for scan %s", want)
		}
	}
}

func TestVersionJSONAndPlain(t *testing.T) {
	// Plain text version check
	code, out, errs := tuner(t, "version")
	if code != exitOK || !strings.Contains(out, "rhythm-tuner dev") || errs != "" {
		t.Errorf("version: exit %d, stdout %q, stderr %q", code, out, errs)
	}

	code, out, errs = tuner(t, "--version")
	if code != exitOK || !strings.Contains(out, "rhythm-tuner dev") || errs != "" {
		t.Errorf("--version: exit %d, stdout %q, stderr %q", code, out, errs)
	}

	// JSON version check
	code, out, errs = tuner(t, "version", "--json")
	if code != exitOK || errs != "" {
		t.Fatalf("version --json: exit %d, stderr %q", code, errs)
	}

	var doc struct {
		Schema  string `json:"schema"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("version --json output is not valid JSON: %v\nOutput: %s", err, out)
	}

	if doc.Schema != "rhythm-version/v1" {
		t.Errorf("expected schema rhythm-version/v1, got %q", doc.Schema)
	}
	if doc.Name != "rhythm-tuner" {
		t.Errorf("expected name rhythm-tuner, got %q", doc.Name)
	}
	if doc.Version != "dev" {
		t.Errorf("expected version dev, got %q", doc.Version)
	}
}
