package netvuln_v1

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/Ullaakut/nmap/v3"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	log.SetLevel(log.FatalLevel)
	os.Exit(m.Run())
}

func TestParseVulnersElement(t *testing.T) {

	var tests = []struct {
		elements []nmap.Element
		expected vulnersElement
	}{
		{
			[]nmap.Element{{Key: "cvss", Value: "5.0"}, {Key: "is_exploit", Value: "false"}},
			vulnersElement{},
		},
		{
			[]nmap.Element{{Key: "cvss", Value: "5.0"}, {Key: "is_exploit", Value: "true"}, {Key: "id", Value: "El"}},
			vulnersElement{true, "El", 5},
		},
	}

	t.Run("empty_elements", func(t *testing.T) {
		result, err := parseVulnersElement([]nmap.Element{})
		if err == nil || err != ErrParseVulners {
			t.Errorf("didn't get the expected error: got: '%s', result: %+v; expected: '%s'", err, result, ErrParseVulners)
		}
	})

	t.Run("invalid_cvss", func(t *testing.T) {
		elements := []nmap.Element{{Key: "is_exploit", Value: "true"}, {Key: "cvss", Value: "abcd"}}
		result, err := parseVulnersElement(elements)
		if err == nil || !errors.Is(err, strconv.ErrSyntax) {
			t.Errorf("didn't get the expected error: got: '%s', result: %+v; expected: '%s'", err, result, strconv.ErrSyntax)
		}
	})

	for _, tt := range tests {
		testname := fmt.Sprintf("is_exploit: %v", tt.expected.isExploit)

		t.Run(testname, func(t *testing.T) {
			result, err := parseVulnersElement(tt.elements)
			if err != nil {
				t.Error("got unexpected err:", err)
			}

			if result != tt.expected {
				t.Errorf("got %+v; expected: %+v", result, tt.expected)
			}
		})
	}
}

func TestFilterVulnersScript(t *testing.T) {
	testScript := nmap.Script{ID: "test"}
	scripts := []nmap.Script{testScript, {ID: "vulners"}}

	var tests = []struct {
		name     string
		scripts  []nmap.Script
		expected *nmap.Script
	}{
		{"no scripts", []nmap.Script{}, nil},
		{"no vulners", []nmap.Script{testScript}, nil},
		{"vulners", scripts, &scripts[1]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := filterVulnersScript(tt.scripts)
			if script != tt.expected {
				t.Errorf("got: %p: %+v; expected: %p: %+v", script, script, tt.expected, tt.expected)
			}
		})
	}
}

func TestParseVulnersScriptResponse(t *testing.T) {

	script_with_vulns := &nmap.Script{
		ID: "vulners",
		Tables: []nmap.Table{{
			Tables: []nmap.Table{
				{Elements: []nmap.Element{
					{Key: "id", Value: "A"},
					{Key: "Type", Value: "a"},
					{Key: "is_exploit", Value: "true"},
					{Key: "cvss", Value: "5.0"},
				}},
				{Elements: []nmap.Element{
					{Key: "id", Value: "B"},
					{Key: "Type", Value: "b"},
					{Key: "is_exploit", Value: "false"},
					{Key: "cvss", Value: "2.0"},
				}},
				{Elements: []nmap.Element{
					{Key: "id", Value: "C"},
					{Key: "Type", Value: "c"},
					{Key: "is_exploit", Value: "true"},
					{Key: "cvss", Value: "7.8"},
				}},
			},
		}},
	}
	vulns := []*Vulnerability{
		{Identifier: "A", CvssScore: 5},
		{Identifier: "C", CvssScore: 7.8},
	}

	script_without_vulns := &nmap.Script{
		ID: "vulners",
		Tables: []nmap.Table{{
			Tables: []nmap.Table{
				{Elements: []nmap.Element{
					{Key: "id", Value: "A"},
					{Key: "type", Value: "a"},
					{Key: "is_exploit", Value: "false"},
					{Key: "cvss", Value: "5.0"},
				}},
			},
		}},
	}
	emptyVulns := make([]*Vulnerability, 0)

	var tests = []struct {
		name     string
		script   *nmap.Script
		expected []*Vulnerability
	}{
		{
			"no script",
			nil,
			emptyVulns,
		},
		{
			"empty script",
			&nmap.Script{ID: "vulners"},
			emptyVulns,
		},
		{
			"script with vulnerabilities",
			script_with_vulns,
			vulns,
		},
		{
			"script without vulnerabilities",
			script_without_vulns,
			emptyVulns,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns, err := parseVulnersScriptResponse(tt.script)
			if err != nil {
				t.Error("got unexpected err:", err)
			}

			if !reflect.DeepEqual(vulns, tt.expected) {
				t.Errorf("got: %+v; expected: %+v", vulns, tt.expected)
			}
		})
	}
}

const (
	nmapRunDataPath        = "tests_data/nmap_run.json"
	serverResponseDataPath = "tests_data/server_response.json"
)

func TestBuildResponse(t *testing.T) {
	var expected CheckVulnResponse
	if err := unmarshalFromFile(serverResponseDataPath, &expected); err != nil {
		t.Fatal(err)
	}

	var run nmap.Run
	if err := unmarshalFromFile(nmapRunDataPath, &run); err != nil {
		t.Fatal(err)
	}

	response, err := buildResponse(&run)
	if err != nil {
		t.Error("got unexpected error:", err)
	}

	// https://blog.gojek.io/relooking-at-golangs-reflect-deepequal/
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal("failed to marshal response:", err)
	}

	response = &CheckVulnResponse{}
	if err = json.Unmarshal(data, response); err != nil {
		t.Fatal("failed to unmarshal response:", err)
	}

	if !reflect.DeepEqual(response.Results, expected.Results) {
		t.Errorf("got: %+v;\n expected: %+v", response, &expected)
	}
}

func unmarshalFromFile(filePath string, v any) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return errors.Wrapf(err, "failed to read nmap run data from file %s", filePath)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return errors.Wrapf(err, "failed to unmarshal nmap run data")
	}

	return nil
}
