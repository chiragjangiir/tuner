// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// rhythm-tuner is the Tuner binary, normally run as `rhythm tuner`.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/x/term"

	"github.com/RhythmShahriar/rhythm/kit"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// commit is set at build time with -ldflags "-X main.commit=...".
var commit = ""

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1 // findings at or above --fail-on
	exitUsage    = 2
	exitError    = 3 // a target couldn't be scanned, or --fail-on can't trust the result
	exitCanceled = 130
)

// main runs the CLI with the process's arguments and exits with its code.
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run dispatches to a subcommand, the interactive picker or the scan.
// It returns the exit code, so tests can call it like main.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd()) {
			return pick(stdout, stderr)
		}
		usage(stdout)
		return exitOK
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	case "-v", "--version", "version":
		for _, a := range args[1:] {
			if a == "--json" || a == "-json" {
				doc := struct {
					Schema  string `json:"schema"`
					Name    string `json:"name"`
					Version string `json:"version"`
					Commit  string `json:"commit"`
				}{
					Schema:  "rhythm-version/v1",
					Name:    "rhythm-tuner",
					Version: version,
					Commit:  commit,
				}
				if err := json.NewEncoder(stdout).Encode(doc); err != nil {
					fmt.Fprintln(stderr, err)
					return exitError
				}
				return exitOK
			}
		}
		if commit != "" {
			fmt.Fprintf(stdout, "rhythm-tuner %s (commit %s)\n", version, commit)
		} else {
			fmt.Fprintln(stdout, "rhythm-tuner", version)
		}
		return exitOK
	case "scan", "s":
		return scan(args[1:], stdout, stderr)
	case "checks", "ls":
		return listChecks(args[1:], stdout, renamed(stderr))
	case "update":
		return cmdUpdate(args[1:], stdout, renamed(stderr))
	}
	if c := lookupCommand(args[0]); c != nil {
		return c.Run(args[1:], stdout, renamed(stderr))
	}
	printErr(stderr, "", unknownCommand(args[0]))
	return exitUsage
}

// invokedAsEnv is set by the rhythm router to what the user typed, such
// as "rhythm tuner" or "rhythm t", so help and hints name a command that
// works. A binary run on its own goes by its file name instead.
const invokedAsEnv = "RHYTHM_INVOKED_AS"

// argv0 is how the binary was started. Tests change it.
var argv0 = os.Args[0]

// cmdName is the command people type to run Tuner: "rhythm tuner" through
// the rhythm router, else the binary's own name, such as rhythm-tuner
// after go install.
func cmdName() string {
	if s := strings.TrimSpace(os.Getenv(invokedAsEnv)); s != "" && len(s) <= 64 && printable(s) {
		return s
	}
	base := argv0[strings.LastIndexAny(argv0, `/\`)+1:]
	if len(base) > 4 && strings.EqualFold(base[len(base)-4:], ".exe") {
		base = base[:len(base)-4]
	}
	if base == "" || !printable(base) {
		return "rhythm-tuner"
	}
	return base
}

// named replaces every "rhythm tuner" in a help or hint text with the
// name Tuner was started as, so a command it suggests works as typed.
func named(s string) string {
	if n := cmdName(); n != "rhythm tuner" {
		return strings.ReplaceAll(s, "rhythm tuner", n)
	}
	return s
}

// renamed wraps a subcommand's stderr so its messages, written as
// "rhythm tuner: ...", name the command Tuner was started as.
func renamed(w io.Writer) io.Writer {
	if n := cmdName(); n != "rhythm tuner" {
		return renamer{w, n}
	}
	return w
}

// renamer is renamed's writer. Each message is one Write, so a name is
// never split across two.
type renamer struct {
	w    io.Writer
	name string
}

// Write writes p with every "rhythm tuner" replaced by the name in use.
func (r renamer) Write(p []byte) (int, error) {
	if _, err := r.w.Write(bytes.ReplaceAll(p, []byte("rhythm tuner"), []byte(r.name))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// printable reports whether s has no control characters, so it can go in
// help text without moving the cursor or ringing the bell.
func printable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// usageLine is one command in the Usage list: what to type and a
// summary.
type usageLine struct {
	cmd, summary string
}

// The Usage list's layout: summaries start in the column of the flag
// descriptions below them. No line runs past usageWidth.
const (
	usageCmdWidth = 34
	usageWidth    = 80
)

// formatUsage lines up the summaries in one column and wraps them at
// usageWidth. A command too long for its column gets a line of its own,
// with the summary below it.
func formatUsage(lines []usageLine) string {
	indent := strings.Repeat(" ", usageCmdWidth+3)
	var b strings.Builder
	for _, l := range lines {
		if l.summary == "" {
			fmt.Fprintf(&b, "  %s\n", l.cmd)
			continue
		}
		summary := wrapWords(l.summary, usageWidth-len(indent))
		if len(l.cmd) > usageCmdWidth {
			fmt.Fprintf(&b, "  %s\n", l.cmd)
		} else {
			fmt.Fprintf(&b, "  %-*s %s\n", usageCmdWidth, l.cmd, summary[0])
			summary = summary[1:]
		}
		for _, s := range summary {
			fmt.Fprintf(&b, "%s%s\n", indent, s)
		}
	}
	return b.String()
}

// wrapWords breaks text into lines of at most width bytes, between words.
// A word longer than width gets a line of its own.
func wrapWords(text string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		switch {
		case line == "":
			line = w
		case len(line)+1+len(w) <= width:
			line += " " + w
		default:
			lines = append(lines, line)
			line = w
		}
	}
	return append(lines, line)
}

// usage prints the top-level help, with the command name as it was run.
func usage(w io.Writer) {
	name := cmdName()
	lines := []usageLine{
		{cmd: name, summary: "interactive picker"},
		{cmd: name + " scan <url>... [flags]", summary: "scan one or more sites"},
		{cmd: name + " scan <dir> [flags]", summary: "scan a site's files on the server"},
		{cmd: name + " checks [flags]", summary: "list the checks (" + name + " checks --help)"},
		{cmd: name + " update [--clear | --prefetch <dir|url>...]", summary: "refresh the check pack and the WordPress and PHP vulnerability data now"},
	}
	fmt.Fprintln(w, kit.Banner("rhythm tuner", version))
	fmt.Fprint(w, "Find what's out of tune in your WordPress & PHP sites.\n\nUsage:\n"+
		formatUsage(append(lines, commandUsage(name)...)))
	fmt.Fprint(w, strings.ReplaceAll(scanHelp()+helpFooter(), "rhythm tuner", name))
}

// scanUsage is rhythm tuner scan --help: the scan commands and flags only.
func scanUsage(w io.Writer) {
	name := cmdName()
	fmt.Fprintln(w, kit.Banner("rhythm tuner", version))
	fmt.Fprint(w, "Usage:\n"+formatUsage([]usageLine{
		{cmd: name + " scan <url>... [flags]", summary: "scan one or more sites"},
		{cmd: name + " scan <dir> [flags]", summary: "scan a site's files on the server"},
	}))
	fmt.Fprint(w, strings.ReplaceAll(scanHelp()+helpFooter(), "rhythm tuner", name))
}

// scanHelp lists the scan flags, extension sections included. Every
// "rhythm tuner" in it and in helpFooter becomes the name Tuner was
// started as.
func scanHelp() string {
	return `
Output:
      --json               JSON report (an array when scanning several targets)
      --json-array         JSON report that is always an array, also for one
                           target; targets that failed appear as
                           {"target": ..., "error": ...}
      --jsonl              one JSON finding per line, streamed as found
      --sarif              SARIF 2.1.0 for GitHub code scanning
      --md                 Markdown for issues and pull requests
  -o, --output <file>      write the report to a file (format by extension)
                           and keep the live view on the terminal; an existing
                           file is replaced only once the new report is complete
  -q, --quiet              findings only
      --plain              no color, boxes or glyphs (screen readers, logs)
      --no-color           no color
  -v, --verbose            log every request to stderr (rhythm tuner -v alone
                           prints the version)

Checks:
      --profile <name>     quick or default (default "default")
      --tags <list>        only checks with these tags, e.g. leak,wordpress
      --exclude-tags <list>
      --id <list>          only these checks; globs allowed, e.g. leak-*
      --exclude-id <list>
      --severity <level>   skip checks below this severity
      --checks <dir>       load checks from a directory
      --no-check-updates   use the built-in checks, not the latest check pack
      --no-vulns           skip known-vulnerability matching
      --offline            use cached vulnerability data and check pack only;
                           no update check either. RHYTHM_OFFLINE=1 also skips
                           the update check

Requests:
      --rate <n>           max requests per second per site (default 5, or 50
                           for localhost and private or link-local addresses)
  -c, --concurrency <n>    requests in flight per site (default 10)
      --timeout <d>        per-request timeout (default 10s)
      --retries <n>        retries after network errors or 429/503 (default 2)
      --max-time <d>       stop the whole scan after this long
  -A, --user-agent <ua>    User-Agent header
  -H, --header <h>         extra header, "Name: value" (repeatable)
      --cookie <c>         Cookie header, e.g. "session=abc"
                           -H and --cookie go only to the site you named,
                           never to another host a redirect leads to
      --proxy <url>        http, https or socks5 proxy (HTTPS_PROXY also works)
  -k, --insecure           don't verify TLS certificates

Local scans (when the target is a directory):
      --php <binary>       php to ask for the PHP version (default: php on PATH)
                           Reads WordPress, plugin, theme and composer.lock
                           versions from disk, reviews wp-config.php and finds
                           files that don't belong in a web root. Never runs
                           site code; request flags don't apply.

Batch and CI:
  -l, --list <file>        read targets from a file, one per line
      --stdin              read targets from stdin
      --parallel <n>       sites scanned at once (default 4)
      --fail-on <level>    exit 1 if a finding is at or above this severity
      --min-confidence <c> confirmed or likely (default "likely"); with
                           confirmed, --fail-on and --fail-on-new skip
                           likely findings such as CVEs a distro PHP build
                           may have patched
      --baseline <file>    hide findings already in this JSON report
      --allow-missing-vulns
                           let --fail-on and --fail-on-new pass a site whose
                           vulnerability data couldn't be fetched
                           (otherwise exit 3)
      --allow-partial      let --fail-on and --fail-on-new pass a scan that
                           was blocked or cut short, or whose --integrity
                           checksums couldn't be loaded (otherwise exit 3)
      --config <file>      read settings from this file instead of .tuner.yml
      --no-config          don't read .tuner.yml; use it in folders you
                           don't trust
                           A .tuner.yml in the current folder sets targets,
                           profile, rate, concurrency, fail_on,
                           min_confidence, baseline, headers (${TUNER_VAR}
                           reads the environment; only TUNER_ names), tags,
                           ids and ignore entries (id, path, reason, until).
                           Flags win over it. When it sets the targets, -H,
                           --cookie and ${TUNER_VAR} headers need targets on
                           the command line.

` + extensionHelp()
}

// helpFooter explains where data comes from, the exit codes and examples.
func helpFooter() string {
	return `Vulnerability data comes from WPVulnerability (CC0), api.wordpress.org and
php.net, plus Wordfence Intelligence when TUNER_WORDFENCE_KEY holds an API
key; Composer packages are matched with OSV.dev. New checks arrive as a
check pack from Tuner's GitHub releases, signed with Ed25519; a build
without the signing key uses its built-in checks, as --no-check-updates
does. Both are cached under your user cache directory and refreshed
automatically once a day; TUNER_VULN_API, TUNER_WPORG_API, TUNER_WPDL_API,
TUNER_PHPNET_API, TUNER_OSV_API, TUNER_WORDFENCE_API and TUNER_CHECKS_URL
point Tuner at mirrors.
TUNER_SMTP_PASSWORD is the --notify email password; TUNER_SERVE_TOKEN and
TUNER_WEBHOOK_SECRET are serve's API token and webhook signing secret.

Exit codes: 0 ok · 1 findings at --fail-on or new findings at --fail-on-new ·
2 usage error · 130 interrupted · 3 scan error, --fail-on or --fail-on-new
with missing vulnerability data or a partial scan, or a notification that
failed under --notify-strict

Examples:
  rhythm tuner scan example.com
  rhythm tuner scan example.com --profile quick -o report.md
  rhythm tuner scan -l sites.txt --json > results.json
  rhythm tuner scan staging.example.com -H "Authorization: Bearer $TOKEN" -k
  rhythm tuner scan example.com --sarif --fail-on high > tuner.sarif
  rhythm tuner scan /var/www/example.com --php /usr/bin/php8.3
`
}
