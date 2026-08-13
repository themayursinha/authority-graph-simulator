// Command authority-graph-simulator reads one JSON request and emits one
// deterministic JSON receipt for a counterfactual MCP capability delegation.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/themayursinha/authority-graph-simulator/authoritygraph"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "authority-graph-simulator:", err)
		os.Exit(1)
	}
}

// run decodes one request file, evaluates it, and writes exactly one receipt.
// A deny is an authorization result, not an error. Errors are reserved for
// usage, unreadable/malformed request input, or encoding failures, and never
// leave a partial receipt on stdout.
func run(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: authority-graph-simulator <input.json>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	req, err := decodeRequest(data)
	if err != nil {
		return err
	}
	receipt := authoritygraph.Evaluate(req)
	out, err := receipt.Encode()
	if err != nil {
		return err
	}
	_, err = stdout.Write(out)
	return err
}

// decodeRequest strictly decodes exactly one JSON object: a top-level array,
// scalar, or null is rejected, unknown fields are rejected, and trailing JSON
// after the object is rejected.
func decodeRequest(data []byte) (authoritygraph.Request, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return authoritygraph.Request{}, errors.New("invalid request JSON: expected a single JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var req authoritygraph.Request
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("invalid request JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return req, errors.New("invalid request JSON: trailing data after object")
		}
		return req, fmt.Errorf("invalid request JSON: %w", err)
	}
	return req, nil
}
