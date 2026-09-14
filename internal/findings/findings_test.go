package findings

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate docs/findings.md")

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"pass", SeverityPass, false},
		{"INFO", SeverityInfo, false},
		{"Low", SeverityLow, false},
		{"medium", SeverityMedium, false},
		{"high", SeverityHigh, false},
		{"critical", SeverityCritical, false},
		{"none", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseSeverity(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityOrdering(t *testing.T) {
	all := Severities()
	for i := 1; i < len(all); i++ {
		if all[i-1] <= all[i] {
			t.Errorf("%v should rank above %v", all[i-1], all[i])
		}
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	for _, s := range Severities() {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var got Severity
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got != s {
			t.Errorf("round trip %v -> %s -> %v", s, b, got)
		}
	}
	if _, err := json.Marshal(Severity(0)); err == nil {
		t.Error("marshalling zero severity should fail")
	}
}

func TestSortIsDeterministic(t *testing.T) {
	r := Rule{ID: "MAIL-X-001", Severity: SeverityLow}
	fs := []Finding{
		r.New("b", "x"),
		r.New("a", "x").WithSeverity(SeverityHigh),
		{ID: "MAIL-A-002", Severity: SeverityLow},
		r.New("a", "x"),
		{ID: "MAIL-A-001", Severity: SeverityPass},
	}
	Sort(fs)
	var got []string
	for _, f := range fs {
		got = append(got, fmt.Sprintf("%s/%s/%s", f.Severity, f.ID, f.Subject))
	}
	want := []string{"high/MAIL-X-001/a", "low/MAIL-A-002/", "low/MAIL-X-001/a", "low/MAIL-X-001/b", "pass/MAIL-A-001/"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestThresholds(t *testing.T) {
	fs := []Finding{
		{ID: "a", Severity: SeverityPass},
		{ID: "b", Severity: SeverityMedium},
		{ID: "c", Severity: SeverityLow},
	}
	if got := Max(fs); got != SeverityMedium {
		t.Errorf("Max = %v", got)
	}
	if got := Max(nil); got != 0 {
		t.Errorf("Max(nil) = %v", got)
	}
	if got := len(AtLeast(fs, SeverityLow)); got != 2 {
		t.Errorf("AtLeast(low) = %d", got)
	}
	c := Counts(fs)
	if c["medium"] != 1 || c["critical"] != 0 || len(c) != 6 {
		t.Errorf("Counts = %v", c)
	}
}

func TestNewDoesNotAliasRule(t *testing.T) {
	r := Rule{ID: "MAIL-X-001", References: []string{"a"}}
	f := r.New("s", "d", "e1")
	f.References[0] = "changed"
	if r.References[0] != "a" {
		t.Error("finding shares references slice with rule")
	}
	g := f.WithEvidence("e2")
	if len(f.Evidence) != 1 || len(g.Evidence) != 2 {
		t.Error("WithEvidence mutated the original")
	}
}

var idPattern = regexp.MustCompile(`^MAIL-([A-Z]+)-(\d{3})$`)

var componentPrefix = map[Component]string{
	ComponentDNS:         "DNS",
	ComponentMX:          "MX",
	ComponentSPF:         "SPF",
	ComponentDKIM:        "DKIM",
	ComponentDMARC:       "DMARC",
	ComponentMTASTS:      "MTASTS",
	ComponentTLSRPT:      "TLSRPT",
	ComponentMessage:     "MSG",
	ComponentReceived:    "RCVD",
	ComponentAuthResults: "AR",
	ComponentARC:         "ARC",
}

func TestCatalogConsistency(t *testing.T) {
	for _, r := range Rules() {
		m := idPattern.FindStringSubmatch(r.ID)
		if m == nil {
			t.Errorf("%s: ID does not match %s", r.ID, idPattern)
			continue
		}
		if want := componentPrefix[r.Component]; m[1] != want {
			t.Errorf("%s: component %q expects prefix %q", r.ID, r.Component, want)
		}
		if !r.Severity.Valid() {
			t.Errorf("%s: invalid severity", r.ID)
		}
		switch r.Category {
		case CategoryViolation, CategoryWeakness, CategoryHardening, CategoryInformational:
		default:
			t.Errorf("%s: invalid category %q", r.ID, r.Category)
		}
		if r.Title == "" {
			t.Errorf("%s: empty title", r.ID)
		}
		if r.Severity > SeverityInfo && r.Recommendation == "" {
			t.Errorf("%s: severity %v requires a recommendation", r.ID, r.Severity)
		}
	}
}

// TestCatalogDocumented keeps docs/findings.md in sync with the catalog so
// that any change to a public finding ID is visible in review.
func TestCatalogDocumented(t *testing.T) {
	const path = "../../docs/findings.md"
	want := renderCatalogMarkdown()
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/findings -update)", err)
	}
	if string(got) != want {
		t.Errorf("docs/findings.md is out of date; run: go test ./internal/findings -update")
	}
}

func renderCatalogMarkdown() string {
	order := []Component{ComponentMX, ComponentSPF, ComponentDKIM, ComponentDMARC, ComponentMTASTS, ComponentTLSRPT,
		ComponentMessage, ComponentReceived, ComponentAuthResults, ComponentARC, ComponentDNS}
	byComponent := map[Component][]Rule{}
	for _, r := range Rules() {
		byComponent[r.Component] = append(byComponent[r.Component], r)
	}

	var b strings.Builder
	b.WriteString("# Finding catalog\n\n")
	b.WriteString("Finding IDs are stable across releases. This file is generated from\n")
	b.WriteString("`internal/findings/catalog.go` by `go test ./internal/findings -update`.\n\n")
	b.WriteString("Severity is the default; context may raise or lower it for a specific\nfinding.\n")
	for _, c := range order {
		rules := byComponent[c]
		if len(rules) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n\n", c)
		b.WriteString("| ID | Default severity | Category | Title |\n")
		b.WriteString("|----|------------------|----------|-------|\n")
		for _, r := range rules {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.ID, r.Severity, r.Category, r.Title)
		}
	}
	return b.String()
}
