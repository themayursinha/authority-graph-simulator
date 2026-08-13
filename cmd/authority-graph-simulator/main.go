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
// after the object is rejected. A token-level shape pass runs first so the
// object is also rejected when it contains duplicate keys, case-variant or
// unknown field names, or null for a collection/required field — cases
// encoding/json would otherwise accept silently.
func decodeRequest(data []byte) (authoritygraph.Request, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return authoritygraph.Request{}, errors.New("invalid request JSON: expected a single JSON object")
	}
	if err := checkRequestShape(bytes.NewReader(data)); err != nil {
		return authoritygraph.Request{}, fmt.Errorf("invalid request JSON: %w", err)
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

// jsonFieldKind describes the strict shape expected for one request field.
type jsonFieldKind int

const (
	jsonFieldString    jsonFieldKind = iota // scalar string
	jsonFieldStrings                        // array of strings
	jsonFieldPairArray                      // array of {principal, capability} objects
	jsonFieldEdgeArray                      // array of {from, to, capability} objects
	jsonFieldObject                         // single object
	jsonFieldBool                           // true or false
)

// The request schema is small and fixed, so the shape pass walks it
// explicitly. Null is never meaningful in a request; object keys must be
// spelled exactly and may not repeat. These tables must stay in sync with
// authoritygraph.Request and its nested types.
var (
	requestObjectFields = map[string]jsonFieldKind{
		"principals":                  jsonFieldStrings,
		"capabilities":                jsonFieldStrings,
		"direct_grants":               jsonFieldPairArray,
		"delegations":                 jsonFieldEdgeArray,
		"mandate":                     jsonFieldPairArray,
		"proposed_action":             jsonFieldObject,
		"direct_operation_authorized": jsonFieldBool,
	}
	pairObjectFields = map[string]jsonFieldKind{
		"principal":  jsonFieldString,
		"capability": jsonFieldString,
	}
	edgeObjectFields = map[string]jsonFieldKind{
		"from":       jsonFieldString,
		"to":         jsonFieldString,
		"capability": jsonFieldString,
	}
	actionObjectFields = map[string]jsonFieldKind{
		"type":       jsonFieldString,
		"from":       jsonFieldString,
		"to":         jsonFieldString,
		"capability": jsonFieldString,
	}
)

// checkRequestShape token-scans one JSON object and rejects duplicate keys,
// case-variant or unknown field names, null values, and shape mismatches
// before any value is bound.
func checkRequestShape(r io.Reader) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("expected a single JSON object")
	}
	if err := checkObject(dec, requestObjectFields); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing data after object")
		}
		return err
	}
	return nil
}

// checkObject validates one JSON object against the exact field set: every key
// must be spelled exactly and appear at most once, and each value must match
// its expected kind (null is never accepted). It consumes the object including
// its closing delimiter.
func checkObject(dec *json.Decoder, fields map[string]jsonFieldKind) error {
	seen := make(map[string]bool, len(fields))
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		name := key.(string)
		if seen[name] {
			return fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = true
		kind, ok := fields[name]
		if !ok {
			return fmt.Errorf("unknown field %q", name)
		}
		if err := checkValue(dec, kind); err != nil {
			return fmt.Errorf("field %q: %w", name, err)
		}
	}
	_, err := dec.Token() // consume the closing '}'
	return err
}

func checkValue(dec *json.Decoder, kind jsonFieldKind) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch kind {
	case jsonFieldString:
		if _, ok := tok.(string); !ok {
			return errors.New("expected a string")
		}
		return nil
	case jsonFieldBool:
		if _, ok := tok.(bool); !ok {
			return errors.New("expected a boolean")
		}
		return nil
	case jsonFieldStrings:
		return checkStringArray(dec, tok)
	case jsonFieldPairArray:
		return checkObjectArray(dec, tok, pairObjectFields)
	case jsonFieldEdgeArray:
		return checkObjectArray(dec, tok, edgeObjectFields)
	case jsonFieldObject:
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return errors.New("expected an object")
		}
		return checkObject(dec, actionObjectFields)
	}
	return nil
}

func checkStringArray(dec *json.Decoder, tok json.Token) error {
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return errors.New("expected an array of strings")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if _, ok := tok.(string); !ok {
			return errors.New("expected an array of strings")
		}
	}
	_, err := dec.Token() // consume the closing ']'
	return err
}

func checkObjectArray(dec *json.Decoder, tok json.Token, fields map[string]jsonFieldKind) error {
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return errors.New("expected an array of objects")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return errors.New("expected an array of objects")
		}
		if err := checkObject(dec, fields); err != nil {
			return err
		}
	}
	_, err := dec.Token() // consume the closing ']'
	return err
}
