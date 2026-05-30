// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package failreport implements the automatic, consent-gated, deferred
// GitHub-issue reporting pipeline for unsolved captive-portal environments.
//
// When nowifi cannot bypass a portal it is, by definition, OFFLINE — so an
// issue cannot be filed at failure time. Instead the forensic package is
// queued locally (Enqueue). Later, on any nowifi run that has real internet
// (or a watch reconnect), MaybeOfferPending surfaces the queued report,
// shows a privacy-sanitized preview, and asks the user for consent before
// filing a GitHub issue via their own `gh` CLI. Nothing ever leaves the
// machine without an explicit interactive "y": the automation is the
// notice+prompt, never silent network egress.
package failreport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/bypass"
	"github.com/MikkoParkkola/nowifi/internal/config"
	"github.com/MikkoParkkola/nowifi/internal/forensics"
)

// Entry is the queue metadata for one pending report (meta.json).
type Entry struct {
	ID         string `json:"id"` // queue dir name == package timestamp
	TS         string `json:"ts"`
	Provider   string `json:"provider"`
	SSID       string `json:"ssid,omitempty"`
	Gateway    string `json:"gateway,omitempty"`
	HolesCount int    `json:"holes_count"`
	Submitted  bool   `json:"submitted"`
	IssueURL   string `json:"issue_url,omitempty"`

	dir string // absolute queue dir (not serialized)
}

// queueDir returns ~/.nowifi/pending-reports.
func queueDir() string { return filepath.Join(config.Dir(), "pending-reports") }

// submitFunc is the issue-filing implementation; overridable in tests.
var submitFunc = ghSubmit

// hasInternet reports real connectivity; overridable in tests so the
// consent-flow logic can be exercised without a live network.
var hasInternet = bypass.HasInternet

// Enqueue persists the full (unsanitized) forensic package plus metadata to
// the local queue so it can be filed later when connectivity returns. Storage
// is local-only and full-fidelity; sanitization happens at issue-generation
// time, never here.
func Enqueue(pkg *forensics.Package, ssid string) (string, error) {
	if pkg == nil {
		return "", fmt.Errorf("nil package")
	}
	id := pkg.TS
	if id == "" {
		return "", fmt.Errorf("package has no timestamp")
	}
	dir := filepath.Join(queueDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := writeJSONAtomic(filepath.Join(dir, "package.json"), pkg, 0o600); err != nil {
		return "", err
	}
	meta := &Entry{
		ID: id, TS: pkg.TS, Provider: pkg.Provider, SSID: ssid,
		Gateway: pkg.GW, HolesCount: len(pkg.Holes), Submitted: false,
	}
	if err := writeJSONAtomic(filepath.Join(dir, "meta.json"), meta, 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// List returns queued reports, unsubmitted first, newest within each group.
func List() ([]Entry, error) {
	root := queueDir()
	ents, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, de := range ents {
		if !de.IsDir() {
			continue
		}
		dir := filepath.Join(root, de.Name())
		var m Entry
		if err := readJSON(filepath.Join(dir, "meta.json"), &m); err != nil {
			continue // skip malformed entries rather than fail the whole list
		}
		m.dir = dir
		if m.ID == "" {
			m.ID = de.Name()
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Submitted != out[j].Submitted {
			return !out[i].Submitted // unsubmitted first
		}
		return out[i].TS > out[j].TS // newest first
	})
	return out, nil
}

// PendingCount returns the number of unsubmitted queued reports.
func PendingCount() int {
	es, err := List()
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range es {
		if !e.Submitted {
			n++
		}
	}
	return n
}

// Load returns the full stored package and metadata for a queue id.
func Load(id string) (*forensics.Package, *Entry, error) {
	dir := filepath.Join(queueDir(), id)
	var pkg forensics.Package
	if err := readJSON(filepath.Join(dir, "package.json"), &pkg); err != nil {
		return nil, nil, err
	}
	var m Entry
	if err := readJSON(filepath.Join(dir, "meta.json"), &m); err != nil {
		return nil, nil, err
	}
	m.dir = dir
	return &pkg, &m, nil
}

// MarkSubmitted records that a report was filed (idempotent).
func MarkSubmitted(id, issueURL string) error {
	dir := filepath.Join(queueDir(), id)
	var m Entry
	if err := readJSON(filepath.Join(dir, "meta.json"), &m); err != nil {
		return err
	}
	m.Submitted = true
	m.IssueURL = issueURL
	return writeJSONAtomic(filepath.Join(dir, "meta.json"), &m, 0o600)
}

// MaybeOfferPending is the automatic entry point. It is a no-op (no output)
// when reporting is disabled, when there is no internet, or when nothing is
// pending — so it is safe to call at the start of every nowifi run. Otherwise
// it shows a sanitized preview of each pending report and asks for consent
// before filing. When `in` is not interactive it prints a one-line notice and
// does not block. Errors are never fatal to the caller.
func MaybeOfferPending(in io.Reader, out io.Writer) error {
	cfg, _ := config.Load()
	if cfg != nil && !cfg.ReportFailures {
		return nil
	}
	if !hasInternet() {
		return nil
	}
	es, err := List()
	if err != nil {
		return err
	}
	var pending []Entry
	for _, e := range es {
		if !e.Submitted {
			pending = append(pending, e)
		}
	}
	if len(pending) == 0 {
		return nil
	}

	if !isInteractive(in) {
		fmt.Fprintf(out, "\n%d unsolved-network forensic report(s) pending — run `nowifi report` to review and submit.\n", len(pending))
		return nil
	}

	reader := bufio.NewReader(in)
	for _, e := range pending {
		pkg, _, err := Load(e.ID)
		if err != nil {
			continue
		}
		san := Sanitize(pkg)
		fmt.Fprintf(out, "\nUnsolved network captured %s — provider=%s ssid=%s, %d open channels.\n",
			e.TS, dashIfEmpty(e.Provider), dashIfEmpty(e.SSID), e.HolesCount)
		fmt.Fprintf(out, "Filing a GitHub issue (your MAC + nearby device MACs are redacted to vendor IDs) helps build a bypass for this environment.\n")
		fmt.Fprintf(out, "Submit this report to github.com/%s? [y/N] ", repoSlug)
		line, _ := reader.ReadString('\n')
		if !isYes(line) {
			fmt.Fprintln(out, "Skipped (kept locally).")
			continue
		}
		url, err := submitFunc(IssueTitle(san, e.SSID), IssueBody(san, e.SSID))
		if err != nil {
			fmt.Fprintf(out, "Could not file automatically (%v).\nCreate it manually at https://github.com/%s/issues/new — body printed below:\n\n%s\n", err, repoSlug, IssueBody(san, e.SSID))
			continue
		}
		_ = MarkSubmitted(e.ID, url)
		fmt.Fprintf(out, "Filed: %s\n", url)
	}
	return nil
}

const repoSlug = "MikkoParkkola/nowifi"

// SubmitEntry sanitizes and files a single queued report by id, then marks it
// submitted. Used by the `nowifi report --yes` non-interactive path. Returns
// the rendered sanitized body alongside any error so callers can fall back to
// printing it for manual filing when gh is unavailable.
func SubmitEntry(id string) (issueURL, body string, err error) {
	pkg, e, lerr := Load(id)
	if lerr != nil {
		return "", "", lerr
	}
	san := Sanitize(pkg)
	body = IssueBody(san, e.SSID)
	url, serr := submitFunc(IssueTitle(san, e.SSID), body)
	if serr != nil {
		return "", body, serr
	}
	_ = MarkSubmitted(id, url)
	return url, body, nil
}

// --- privacy sanitization ---

var macRE = regexp.MustCompile(`(?i)^([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}):[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}$`)

// redactMAC keeps the vendor OUI (first three octets) and masks the
// device-specific half. Non-MAC strings are returned unchanged.
func redactMAC(s string) string {
	m := macRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return s
	}
	return m[1] + ":xx:xx:xx"
}

// Sanitize deep-copies the package and redacts every MAC (nearby third-party
// devices in Raw.ARP and the user's own Raw.SelfMAC) to vendor-OUI-only,
// leaving all solve-it intel (IPs, provider, channels, pax-api) intact.
func Sanitize(p *forensics.Package) *forensics.Package {
	if p == nil {
		return nil
	}
	var cp forensics.Package
	b, _ := json.Marshal(p)
	_ = json.Unmarshal(b, &cp)
	for i := range cp.Raw.ARP {
		cp.Raw.ARP[i].MAC = redactMAC(cp.Raw.ARP[i].MAC)
	}
	cp.Raw.SelfMAC = redactMAC(cp.Raw.SelfMAC)
	return &cp
}

// --- issue rendering ---

// IssueTitle builds a concise, deduplicable issue title.
func IssueTitle(p *forensics.Package, ssid string) string {
	prov := dashIfEmpty(p.Provider)
	if ssid != "" {
		prov = fmt.Sprintf("%s (%s)", prov, ssid)
	}
	return fmt.Sprintf("Unsolved captive portal: %s — %d open channels", prov, len(p.Holes))
}

// IssueBody renders the sanitized package as a GitHub issue with all the
// detail needed to build a bypass. Callers MUST pass a Sanitize()d package.
func IssueBody(p *forensics.Package, ssid string) string {
	var b strings.Builder
	b.WriteString("Automated report from `nowifi` — bypass exhausted; this environment is unsolved.\n\n")
	b.WriteString("## Environment\n")
	fmt.Fprintf(&b, "- Provider: `%s`\n", dashIfEmpty(p.Provider))
	if ssid != "" {
		fmt.Fprintf(&b, "- SSID: `%s`\n", ssid)
	}
	fmt.Fprintf(&b, "- Gateway: `%s`\n", dashIfEmpty(p.GW))
	fmt.Fprintf(&b, "- Interface: `%s`\n", dashIfEmpty(p.Iface))
	fmt.Fprintf(&b, "- Captured: `%s`\n\n", p.TS)

	b.WriteString("## Ranked holes (candidate techniques)\n\n")
	if len(p.Holes) == 0 {
		b.WriteString("_none found — fully sealed environment_\n\n")
	} else {
		b.WriteString("| Severity | Technique | Detail |\n|---|---|---|\n")
		for _, h := range p.Holes {
			fmt.Fprintf(&b, "| %s | `%s` | %s |\n", h.Severity, h.Technique, strings.ReplaceAll(h.Detail, "|", "\\|"))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Enforcement control plane (pax-api / portal)\n\n")
	if len(p.Raw.PaxAPI) == 0 {
		b.WriteString("_no pax-api endpoints captured_\n\n")
	} else {
		b.WriteString("| Endpoint | Status |\n|---|---|\n")
		for _, e := range p.Raw.PaxAPI {
			fmt.Fprintf(&b, "| `%s` | %d |\n", e.Path, e.StatusCode)
		}
		b.WriteString("\n")
		if pa := p.Raw.PaxAPIAnalysis; pa != nil {
			fmt.Fprintf(&b, "**Recon verdict:** real-API=`%v` swagger-openapi=`%v`\n\n", pa.IsRealAPI, pa.SwaggerIsOpenAPI)
			if len(pa.CandidateResetVectors) > 0 {
				b.WriteString("Candidate reset vectors (recon only — not attempted):\n")
				for _, rv := range pa.CandidateResetVectors {
					fmt.Fprintf(&b, "- `%s`\n", rv)
				}
				b.WriteString("\n")
			}
			for _, note := range pa.Notes {
				fmt.Fprintf(&b, "> %s\n", note)
			}
			b.WriteString("\n")
		}
	}

	if len(p.Raw.Limitations) > 0 {
		b.WriteString("## Capture limitations\n")
		for _, l := range p.Raw.Limitations {
			fmt.Fprintf(&b, "- %s\n", l)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Full machine-readable package\n\n")
	b.WriteString("<details><summary>holes JSON (sanitized)</summary>\n\n```json\n")
	js, _ := json.MarshalIndent(p, "", "  ")
	b.Write(js)
	b.WriteString("\n```\n</details>\n\n")

	b.WriteString("---\n_MAC device-identifiers redacted to vendor OUI for third-party privacy. Filed via `nowifi report` with user consent._\n")
	return b.String()
}

// --- gh submission ---

// ghSubmit files the issue using the user's own authenticated `gh` CLI. No
// token is bundled or read by nowifi. Returns a sentinel error when gh is
// unavailable so the caller can fall back to printing the body.
func ghSubmit(title, body string) (string, error) {
	if _, err := exec.LookPath("gh"); err != nil {
		return "", fmt.Errorf("gh CLI not found")
	}
	tmp, err := os.CreateTemp("", "nowifi-issue-*.md")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(body); err != nil {
		return "", err
	}
	_ = tmp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gh", "issue", "create",
		"--repo", repoSlug, "--title", title, "--body-file", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh issue create: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return firstURL(string(out)), nil
}

// --- helpers ---

func writeJSONAtomic(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func isInteractive(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func isYes(line string) bool {
	s := strings.ToLower(strings.TrimSpace(line))
	return s == "y" || s == "yes"
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

var urlRE = regexp.MustCompile(`https?://\S+`)

func firstURL(s string) string {
	return strings.TrimSpace(urlRE.FindString(s))
}
