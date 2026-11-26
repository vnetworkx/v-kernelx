package vnetworksdk

import (
	"bytes"
	"encoding/json"
)

// CanonicalJSONBytes encodes v as compact canonical JSON with sorted object keys at all depths.
func CanonicalJSONBytes(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func CanonicalJSONString(v any) (string, error) {
	b, err := CanonicalJSONBytes(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
