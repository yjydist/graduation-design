package protocol

import (
	"bytes"
	"testing"
)

type sampleStruct struct {
	Name    string   `json:"name"`
	Count   int64    `json:"count"`
	Note    *string  `json:"note"`
	OptFlag bool     `json:"optFlag,optional"`
	Items   []string `json:"items"`
}

func TestJCSCanonicalizeRFC8785AndUTF16Sorting(t *testing.T) {
	// RFC 8785 Section 3.2.3 key ordering test:
	// UTF-16 surrogate pair for U+10000 (\uD800\uDC00) must sort BEFORE U+E000 (\uE000),
	// even though in UTF-8 U+E000 sorts before U+10000.
	// Also test number normalization (-0 -> 0, 1e-6 -> 0.000001, 1e-7 -> 1e-7) and minimal escaping (<>&/ unescaped).
	input := `{
  "\uE000": "bmp-private",
  "url": "https://a.local/p?x=1&y=<tag>",
  "\ud800\udc00": "supplementary",
  "negZero": -0,
  "smallFixed": 1e-6,
  "smallSci": 1e-7,
  "ctrl": "\b\f\n\r\t\u0001\"\\"
}`
	canon, err := CanonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatalf("CanonicalizeJSON failed: %v", err)
	}
	want := `{"ctrl":"\b\f\n\r\t\u0001\"\\","negZero":0,"smallFixed":0.000001,"smallSci":1e-7,"url":"https://a.local/p?x=1&y=<tag>","` + "\U00010000" + `":"supplementary","` + "\uE000" + `":"bmp-private"}`
	if string(canon) != want {
		t.Fatalf("canonical mismatch:\ngot:  %s\nwant: %s", string(canon), want)
	}
}

func TestJCSRejectsMalformedAndUnsafeInputs(t *testing.T) {
	oversized := make([]byte, MaxJSONBytes+1)
	for i := range oversized {
		oversized[i] = ' '
	}
	oversized[0] = '{'
	oversized[len(oversized)-1] = '}'

	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte("")},
		{"invalid UTF-8", []byte{'"', 0xff, 0xfe, '"'}},
		{"duplicate keys", []byte(`{"a":1,"a":2}`)},
		{"nested duplicate keys", []byte(`{"outer":{"x":1,"x":1}}`)},
		{"unpaired high surrogate", []byte(`{"k":"\uD800abc"}`)},
		{"unpaired low surrogate", []byte(`{"k":"\uDC00"}`)},
		{"high surrogate followed by non-low", []byte(`{"k":"\uD800\u0041"}`)},
		{"integer above 2^53-1", []byte(`{"n":9007199254740992}`)},
		{"integer below -(2^53-1)", []byte(`{"n":-9007199254740992}`)},
		{"float literal exceeding safe magnitude", []byte(`{"n":1e20}`)},
		{"trailing garbage", []byte(`{"a":1} extra`)},
		{"leading zero number", []byte(`{"a":01}`)},
		{"unescaped control char", []byte("{\"a\":\"\x01\"}")},
		{"oversized input > 256 KiB", oversized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseStrictJSON(tc.raw)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !HasCode(err, ErrCodeInvalidSchema) {
				t.Fatalf("expected error code %s for %s, got %v", ErrCodeInvalidSchema, tc.name, err)
			}
		})
	}

	// Boundary safe integers must succeed.
	if _, err := ParseStrictJSON([]byte(`{"max":9007199254740991,"min":-9007199254740991}`)); err != nil {
		t.Fatalf("safe integer boundary failed: %v", err)
	}
	if _, err := ParseStrictJSON(bytes.Repeat([]byte(" "), MaxJSONBytes-2)); err == nil {
		// spaces alone are invalid empty JSON, test valid object exactly MaxJSONBytes bytes
	}
	exactMax := append([]byte(`{"s":"`), bytes.Repeat([]byte{'a'}, MaxJSONBytes-8)...)
	exactMax = append(exactMax, []byte(`"}`)...)
	if len(exactMax) != MaxJSONBytes {
		t.Fatalf("expected %d bytes, got %d", MaxJSONBytes, len(exactMax))
	}
	if _, err := ParseStrictJSON(exactMax); err != nil {
		t.Fatalf("exact MaxJSONBytes object should succeed, got %v", err)
	}
}

func TestJCSDecodeStrictStructAndSets(t *testing.T) {
	valid := []byte(`{"name":"ok","count":42,"note":null,"items":["a","b"]}`)
	var out sampleStruct
	if err := DecodeStrictJSON(valid, &out); err != nil {
		t.Fatalf("DecodeStrictJSON valid failed: %v", err)
	}
	if out.Name != "ok" || out.Count != 42 || out.Note != nil || len(out.Items) != 2 {
		t.Fatalf("unexpected decoded struct: %+v", out)
	}

	badPayloads := []struct {
		name string
		raw  string
	}{
		{"unknown field", `{"name":"ok","count":1,"note":null,"items":["a"],"extra":1}`},
		{"missing required field", `{"name":"ok","count":1,"note":null}`},
		{"null on non-nullable string", `{"name":null,"count":1,"note":null,"items":["a"]}`},
		{"float literal on int64 field", `{"name":"ok","count":1.0,"note":null,"items":["a"]}`},
		{"not an object", `["a"]`},
	}
	for _, tc := range badPayloads {
		t.Run(tc.name, func(t *testing.T) {
			var s sampleStruct
			err := DecodeStrictJSON([]byte(tc.raw), &s)
			if !HasCode(err, ErrCodeInvalidSchema) {
				t.Fatalf("expected %s for %s, got %v", ErrCodeInvalidSchema, tc.name, err)
			}
		})
	}

	// Set validation tests
	if err := ValidateStringSet("actions", []string{"order.create", "quote.read"}, 32, true); err != nil {
		t.Fatalf("valid sorted set failed: %v", err)
	}
	badSets := []struct {
		name   string
		values []string
		max    int
		sorted bool
	}{
		{"empty", nil, 32, true},
		{"wildcard", []string{"*"}, 32, true},
		{"partial wildcard", []string{"order.*"}, 32, true},
		{"duplicate", []string{"a", "a"}, 32, false},
		{"unsorted", []string{"b", "a"}, 32, true},
		{"empty element", []string{""}, 32, true},
		{"exceeds max", []string{"a", "b", "c"}, 2, true},
	}
	for _, tc := range badSets {
		t.Run("set_"+tc.name, func(t *testing.T) {
			err := ValidateStringSet("set", tc.values, tc.max, tc.sorted)
			if !HasCode(err, ErrCodeInvalidSchema) {
				t.Fatalf("expected %s for set %s, got %v", ErrCodeInvalidSchema, tc.name, err)
			}
		})
	}
}
