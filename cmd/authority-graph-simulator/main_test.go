package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
