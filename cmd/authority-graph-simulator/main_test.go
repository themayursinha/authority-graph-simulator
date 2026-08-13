package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/authority-graph-simulator/authoritygraph"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func runArgs(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := run(args, &buf)
	return buf.String(), err
}

func validRequestJSON() string {
	return `{
  "principals": ["agent-a", "agent-b"],
  "capabilities": ["mcp:payments:refund"],
  "direct_grants": [
    {"principal": "agent-a", "capability": "mcp:payments:refund"}
  ],
  "delegations": [],
  "mandate": [
    {"principal": "agent-a", "capability": "mcp:payments:refund"}
  ],
  "proposed_action": {
    "type": "mcp_capability_delegation",
    "from": "agent-a",
    "to": "agent-b",
    "capability": "mcp:payments:refund"
  },
  "direct_operation_authorized": true
}`
}

func TestRunRejectsUnknownField(t *testing.T) {
	path := writeTemp(t, validRequestJSON()+`,"surprise":1}`)
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for unknown JSON field")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsTrailingJSON(t *testing.T) {
	path := writeTemp(t, validRequestJSON()+` {"again":1}`)
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for trailing JSON")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsMalformedJSON(t *testing.T) {
	path := writeTemp(t, `{"principals": [`)
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsTopLevelArray(t *testing.T) {
	path := writeTemp(t, `[1, 2, 3]`)
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for top-level JSON array")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsNullObject(t *testing.T) {
	path := writeTemp(t, `null`)
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for top-level null")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsEmptyInput(t *testing.T) {
	path := writeTemp(t, ``)
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRejectsUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	out, err := runArgs(t, path)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
	if out != "" {
		t.Fatalf("partial receipt on stdout: %q", out)
	}
}

func TestRunRequiresExactlyOneArgument(t *testing.T) {
	if _, err := runArgs(t); err == nil {
		t.Fatal("expected usage error with no arguments")
	}
	if _, err := runArgs(t, "a.json", "b.json"); err == nil {
		t.Fatal("expected usage error with two arguments")
	}
}

// TestRunDenyIsAnAuthorizationResult proves a deny receipt is not a process
// failure and the receipt is valid JSON.
func TestRunDenyIsAnAuthorizationResult(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "deny-transitive.json")
	out, err := runArgs(t, path)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var receipt authoritygraph.Receipt
	if err := json.Unmarshal([]byte(out), &receipt); err != nil {
		t.Fatalf("stdout is not a valid receipt: %v", err)
	}
	if receipt.Decision != "deny" {
		t.Fatalf("Decision = %q, want %q", receipt.Decision, "deny")
	}
	if receipt.ReasonCode != "authority_exceeds_mandate" {
		t.Fatalf("ReasonCode = %q, want %q", receipt.ReasonCode, "authority_exceeds_mandate")
	}
}

func TestRunDenyTransitiveGoldenFixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "deny-transitive.json")
	expected, err := os.ReadFile(filepath.Join("..", "..", "testdata", "deny-transitive.expected.json"))
	if err != nil {
		t.Fatalf("read expected fixture: %v", err)
	}
	out, err := runArgs(t, fixture)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out != string(expected) {
		t.Fatalf("stdout mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, expected)
	}
}

func TestRunAllowLegitimateGoldenFixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "allow-legitimate.json")
	expected, err := os.ReadFile(filepath.Join("..", "..", "testdata", "allow-legitimate.expected.json"))
	if err != nil {
		t.Fatalf("read expected fixture: %v", err)
	}
	out, err := runArgs(t, fixture)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out != string(expected) {
		t.Fatalf("stdout mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, expected)
	}
}

// TestRunRejectsStrictShapeViolations proves the request decoder is strict
// about more than unknown fields: duplicate keys, case-variant field names,
// null collections/required fields, null array elements, unknown nested
// fields, and type mismatches are all process errors with no partial receipt.
func TestRunRejectsStrictShapeViolations(t *testing.T) {
	valid := validRequestJSON()
	proposedActionBlock := `"proposed_action": {
    "type": "mcp_capability_delegation",
    "from": "agent-a",
    "to": "agent-b",
    "capability": "mcp:payments:refund"
  },`
	cases := []struct {
		name   string
		mutate func() string
	}{
		{"duplicate top-level key", func() string {
			return strings.Replace(valid, `"direct_operation_authorized": true
}`, `"direct_operation_authorized": true,
  "principals": ["agent-a"]
}`, 1)
		}},
		{"case-variant field name", func() string {
			return strings.Replace(valid, `"direct_operation_authorized": true`, `"DIRECT_OPERATION_AUTHORIZED": true`, 1)
		}},
		{"null slice field", func() string {
			return strings.Replace(valid, `"delegations": []`, `"delegations": null`, 1)
		}},
		{"null principals collection", func() string {
			return strings.Replace(valid, `"principals": ["agent-a", "agent-b"],`, `"principals": null,`, 1)
		}},
		{"null element in array", func() string {
			return strings.Replace(valid, `"principals": ["agent-a", "agent-b"],`, `"principals": ["agent-a", null],`, 1)
		}},
		{"null nested required field", func() string {
			return strings.Replace(valid, `"type": "mcp_capability_delegation"`, `"type": null`, 1)
		}},
		{"null proposed action", func() string {
			return strings.Replace(valid, proposedActionBlock, `"proposed_action": null,`, 1)
		}},
		{"unknown nested field", func() string {
			return strings.Replace(valid, `"to": "agent-b",`, `"to": "agent-b",
    "surprise": 1,`, 1)
		}},
		{"duplicate nested key", func() string {
			return strings.Replace(valid, `    "capability": "mcp:payments:refund"
  },`, `    "capability": "mcp:payments:refund",
    "capability": "mcp:payments:refund"
  },`, 1)
		}},
		{"duplicate key in grant element", func() string {
			return strings.Replace(valid, `{"principal": "agent-a", "capability": "mcp:payments:refund"}`, `{"principal": "agent-a", "principal": "agent-a", "capability": "mcp:payments:refund"}`, 1)
		}},
		{"type mismatch bool field", func() string {
			return strings.Replace(valid, `"direct_operation_authorized": true`, `"direct_operation_authorized": "yes"`, 1)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.mutate())
			out, err := runArgs(t, path)
			if err == nil {
				t.Fatal("expected error for strict shape violation")
			}
			if out != "" {
				t.Fatalf("partial receipt on stdout: %q", out)
			}
		})
	}
}
