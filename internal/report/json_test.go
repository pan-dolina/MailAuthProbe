package report_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/pan-dolina/mailauthprobe/internal/analyzer"
	"github.com/pan-dolina/mailauthprobe/internal/report"
)

type schemaDoc struct {
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
	Defs       map[string]struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Pattern string   `json:"pattern"`
			Enum    []string `json:"enum"`
		} `json:"properties"`
	} `json:"$defs"`
}

func loadSchema(t *testing.T) schemaDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", "report-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s schemaDoc
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// checkAgainstSchema verifies the parts of the schema that consumers rely
// on: required top-level keys and the finding structure.
func checkAgainstSchema(t *testing.T, raw []byte) {
	t.Helper()
	s := loadSchema(t)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range s.Required {
		if _, ok := doc[key]; !ok {
			t.Errorf("missing required key %q", key)
		}
	}
	var version string
	_ = json.Unmarshal(doc["schema_version"], &version)
	if version != report.SchemaVersion {
		t.Errorf("schema_version = %q", version)
	}
	var fs []map[string]any
	if err := json.Unmarshal(doc["findings"], &fs); err != nil {
		t.Fatal(err)
	}
	def := s.Defs["finding"]
	idRE := regexp.MustCompile(def.Properties["id"].Pattern)
	for _, f := range fs {
		for _, key := range def.Required {
			if _, ok := f[key]; !ok {
				t.Errorf("finding %v lacks %q", f["id"], key)
			}
		}
		if id, _ := f["id"].(string); !idRE.MatchString(id) {
			t.Errorf("finding id %q does not match schema pattern", id)
		}
		for _, enumKey := range []string{"severity", "category"} {
			if v, _ := f[enumKey].(string); !slices.Contains(def.Properties[enumKey].Enum, v) {
				t.Errorf("finding %v: %s %q not in schema enum", f["id"], enumKey, v)
			}
		}
	}
}

func TestJSONMatchesSchema(t *testing.T) {
	domain := analyzer.Domain(context.Background(), "test.example", analyzer.Options{Resolver: zone(t), DKIMSelectors: []string{"s2026"}})
	for name, rep := range map[string]*report.Report{
		"domain":  domain,
		"message": messageReport(t, "dkim-multiple.eml"),
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := report.WriteJSON(&buf, rep); err != nil {
				t.Fatal(err)
			}
			checkAgainstSchema(t, buf.Bytes())
		})
	}
}

func TestJSONIsDeterministic(t *testing.T) {
	var outputs []string
	for range 3 {
		rep := messageReport(t, "valid.eml")
		var buf bytes.Buffer
		if err := report.WriteJSON(&buf, rep); err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, buf.String())
	}
	if outputs[0] != outputs[1] || outputs[1] != outputs[2] {
		t.Error("JSON output differs between identical runs")
	}
}

func TestJSONEmptyCollections(t *testing.T) {
	rep := &report.Report{SchemaVersion: report.SchemaVersion, Kind: report.KindDomain, Target: "x.example"}
	rep.Finalize(0)
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	if doc["findings"] == nil || doc["errors"] == nil {
		t.Errorf("findings and errors must be arrays, not null: %s", buf.String())
	}
	if doc["summary"].(map[string]any)["highest_severity"] != "none" {
		t.Errorf("summary = %v", doc["summary"])
	}
}
