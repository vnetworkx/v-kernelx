package vnetworksdk

import (
	"bytes"
	"encoding/json"
)

// CanonicalJSONBytes encodes v as compact canonical JSON with sorted object keys at all depths
// without HTML escaping, matching Rust serde_json / JS JSON.stringify / Python json.dumps.
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
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func CanonicalJSONString(v any) (string, error) {
	b, err := CanonicalJSONBytes(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
