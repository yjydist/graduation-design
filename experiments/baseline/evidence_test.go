package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEvidenceCSVPlanNullsAndWhitelist(t *testing.T) {
	in, _ := Baseline(1109)
	dir := filepath.Join(t.TempDir(), "attempt")
	e, err := NewEvidence(dir, "run-test", in)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Requests) != 24 || len(e.Orders) != 12 {
		t.Fatal("incomplete plan")
	}
	stamp := time.Date(2026, 11, 16, 4, 5, 6, 7, time.UTC)
	r := e.Requests[0]
	r["started_at"] = stamp
	r["execute_ns"] = int64(123456789)
	r["amount_minor"] = int64(80000)
	r["request_id"] = "with,comma\nline"
	r["private_key"] = "secret-key"
	r["full_disclosure"] = "secret-disclosure"
	if err = e.Save(); err != nil {
		t.Fatal(err)
	}
	for file, columns := range map[string]string{"requests.csv": RequestColumns, "order_checks.csv": OrderColumns} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rows[0], strings.Split(columns, ",")) {
			t.Fatalf("column order changed: %s", file)
		}
		if strings.Contains(string(raw), "secret-") {
			t.Fatal("export escaped whitelist")
		}
		if file == "requests.csv" {
			m := map[string]string{}
			for n, k := range rows[0] {
				m[k] = rows[1][n]
			}
			if m["revision"] != "null" || m["execute_ns"] != "123456789" || m["started_at"] != stamp.Format(time.RFC3339Nano) || m["request_id"] != "with,comma\nline" {
				t.Fatalf("invalid CSV encoding: %v", m)
			}
		}
	}
	for _, file := range []string{"manifest.json", "summary.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(raw) {
			t.Fatal("invalid JSON")
		}
	}
	if _, err = NewEvidence(dir, "overwrite", in); err == nil {
		t.Fatal("attempt directory was reused")
	}
}

func TestRequestAccountingIncludesDenialsAndMissingActions(t *testing.T) {
	in, _ := Baseline(1109)
	e, err := NewEvidence(filepath.Join(t.TempDir(), "attempt"), "run", in)
	if err != nil {
		t.Fatal(err)
	}
	for n, disposition := range []string{"allowed", "denied", "error", "timeout"} {
		e.Requests[n]["disposition"] = disposition
	}
	a := e.Account()
	if a["planned"] != 24 || a["started"] != 4 || a["dropped"] != 20 || a["completed"] != 3 || a["allowed"] != 1 || a["denied"] != 1 || a["error"] != 1 || a["timeout"] != 1 {
		t.Fatalf("incorrect accounting: %v", a)
	}
	if a["planned"] != a["started"]+a["dropped"] || a["started"] != a["completed"]+a["timeout"] || a["completed"] != a["allowed"]+a["denied"]+a["error"] {
		t.Fatal("request accounting does not balance")
	}
}
