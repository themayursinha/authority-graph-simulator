package authoritygraph

import "encoding/json"

// Encode returns the deterministic JSON encoding of the receipt.
//
// Field order follows the Receipt struct declaration and every authority-pair
// slice is already lexicographically sorted by the evaluator, so the encoding
// is byte-stable for identical declarations regardless of input order.
func (r Receipt) Encode() ([]byte, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
