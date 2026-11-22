package protocol_test

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/protocol"
	"grad/protocol/registry"
)

type embeddedMeta struct {
	Version int64 `json:"version"`
}

type sampleStruct struct {
	embeddedMeta
	Name    string         `json:"name"`
	Count   int64          `json:"count"`
	Small   uint64         `json:"small,optional"`
	Note    *string        `json:"note"`
	OptFlag bool           `json:"optFlag,optional"`
	Items   []string       `json:"items"`
	RawCtx  jsontext.Value `json:"rawCtx,omitempty"`
}

func TestCanonicalizeJSONRFC8785AndUTF16Sorting(t *testing.T) {
	// Surrogate pair U+10000 (\uD800\uDC00) must sort BEFORE U+E000 (\uE000) in UTF-16 code-unit order,
	// even though in UTF-8 U+E000 sorts before U+10000.
	input := `{
  "\uE000": "bmp-private",
  "url": "https://a.local/p?x=1&y=<tag>",
  "\ud800\udc00": "supplementary",
  "negZero": -0,
  "smallFixed": 1e-6,
  "smallSci": 1e-7,
  "ctrl": "\b\f\n\r\t\u0001\"\\"
}`
	canon, err := protocol.CanonicalizeJSON([]byte(input))
	require.NoError(t, err)

	want := `{"ctrl":"\b\f\n\r\t\u0001\"\\","negZero":0,"smallFixed":0.000001,"smallSci":1e-7,"url":"https://a.local/p?x=1&y=<tag>","` + "\U00010000" + `":"supplementary","` + "\uE000" + `":"bmp-private"}`
	assert.Equal(t, want, string(canon))

	// RFC 8785 Section 3.2.3 published sorting test vector.
	rfc8785Vec := `{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`
	rfcCanon, err := protocol.CanonicalizeJSON([]byte(rfc8785Vec))
	require.NoError(t, err)

	wantRFC := `{"\r":"Carriage Return","1":"One","` + "\u0080" + `":"Control","` + "\u00f6" + `":"Latin Small Letter O With Diaeresis","` + "\u20ac" + `":"Euro Sign","` + "\U0001f600" + `":"Emoji: Grinning Face","` + "\ufb33" + `":"Hebrew Letter Dalet With Dagesh"}`
	assert.Equal(t, wantRFC, string(rfcCanon))

	// DigestJCS, MarshalJCS, and DigestValueJCS consistency.
	d1, err := protocol.DigestJCS([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, protocol.DigestBytes(canon), d1)

	d2, err := protocol.DigestValueJCS(map[string]any{"b": 2, "a": 1})
	require.NoError(t, err)
	m, err := protocol.MarshalJCS(map[string]any{"b": 2, "a": 1})
	require.NoError(t, err)
	assert.Equal(t, `{"a":1,"b":2}`, string(m))
	assert.Equal(t, protocol.DigestBytes(m), d2)

	// Number formatting edge cases: -0.0 -> 0, 100.00 -> 100, 1e+3 -> 1000.
	numCanon, err := protocol.CanonicalizeJSON([]byte(`{"a":-0.0,"b":100.00,"c":1e+3}`))
	require.NoError(t, err)
	assert.Equal(t, `{"a":0,"b":100,"c":1000}`, string(numCanon))

	// MarshalJCS enforces safe integer bounds too.
	_, err = protocol.MarshalJCS(map[string]int64{"tooBig": protocol.MaxSafeInt + 1})
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
}

func TestStrictJSONPayloadLimitAndDepth(t *testing.T) {
	// Exactly MaxJSONBytes (256 KiB) must succeed.
	exactMax := append([]byte(`{"s":"`), bytes.Repeat([]byte{'a'}, protocol.MaxJSONBytes-8)...)
	exactMax = append(exactMax, []byte(`"}`)...)
	require.Len(t, exactMax, protocol.MaxJSONBytes)

	_, err := protocol.CanonicalizeJSON(exactMax)
	require.NoError(t, err)

	// MaxJSONBytes + 1 must fail with PAYLOAD_TOO_LARGE.
	oversized := append([]byte(`{"s":"`), bytes.Repeat([]byte{'a'}, protocol.MaxJSONBytes-7)...)
	oversized = append(oversized, []byte(`"}`)...)
	require.Len(t, oversized, protocol.MaxJSONBytes+1)

	_, err = protocol.CanonicalizeJSON(oversized)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodePayloadTooLarge), "got %v", err)

	var dummy map[string]string
	err = protocol.DecodeStrictJSON(oversized, &dummy)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodePayloadTooLarge), "got %v", err)

	// Exact MaxJSONDepth (64) succeeds.
	depth64 := strings.Repeat(`{"a":`, protocol.MaxJSONDepth) + `1` + strings.Repeat(`}`, protocol.MaxJSONDepth)
	_, err = protocol.CanonicalizeJSON([]byte(depth64))
	require.NoError(t, err)

	arrDepth64 := strings.Repeat(`[`, protocol.MaxJSONDepth) + `1` + strings.Repeat(`]`, protocol.MaxJSONDepth)
	_, err = protocol.CanonicalizeJSON([]byte(arrDepth64))
	require.NoError(t, err)

	// Depth MaxJSONDepth + 1 (65) fails with INVALID_SCHEMA.
	depth65 := strings.Repeat(`{"a":`, protocol.MaxJSONDepth+1) + `1` + strings.Repeat(`}`, protocol.MaxJSONDepth+1)
	_, err = protocol.CanonicalizeJSON([]byte(depth65))
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)

	arrDepth65 := strings.Repeat(`[`, protocol.MaxJSONDepth+1) + `1` + strings.Repeat(`]`, protocol.MaxJSONDepth+1)
	_, err = protocol.CanonicalizeJSON([]byte(arrDepth65))
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)
}

func TestStrictJSONRejectsMalformedDuplicateSurrogateAndUnsafeNumbers(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte("")},
		{"whitespace only", []byte("   \t\n")},
		{"invalid UTF-8", []byte{'"', 0xff, 0xfe, '"'}},
		{"duplicate keys", []byte(`{"a":1,"a":2}`)},
		{"nested duplicate keys", []byte(`{"outer":{"x":1,"x":1}}`)},
		{"duplicate keys inside array object", []byte(`[{"a":1},{"b":1,"b":2}]`)},
		{"escaped duplicate keys", []byte(`{"a":1,"\u0061":2}`)},
		{"unpaired high surrogate", []byte(`{"k":"\uD800abc"}`)},
		{"unpaired low surrogate", []byte(`{"k":"\uDC00"}`)},
		{"high surrogate followed by non-low", []byte(`{"k":"\uD800\u0041"}`)},
		{"invalid escape", []byte(`{"k":"\x41"}`)},
		{"integer above 2^53-1", []byte(`{"n":9007199254740992}`)},
		{"integer below -(2^53-1)", []byte(`{"n":-9007199254740992}`)},
		{"float exceeding safe magnitude", []byte(`{"n":1e20}`)},
		{"float overflow inf", []byte(`{"n":1e309}`)},
		{"trailing garbage", []byte(`{"a":1} extra`)},
		{"two top-level values", []byte(`{"a":1}{"b":2}`)},
		{"leading zero number", []byte(`{"a":01}`)},
		{"unescaped control char", []byte("{\"a\":\"\x01\"}")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := protocol.CanonicalizeJSON(tc.raw)
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)
		})
	}

	// Valid boundary safe integers and valid array of objects with repeated keys across distinct objects.
	_, err := protocol.CanonicalizeJSON([]byte(`{"max":9007199254740991,"min":-9007199254740991}`))
	require.NoError(t, err)

	_, err = protocol.CanonicalizeJSON([]byte(`[{"a":1},{"a":2},{"b":[{"k":"v"},{"k":"w"}]}]`))
	require.NoError(t, err)
}

func TestDecodeStrictJSON(t *testing.T) {
	valid := []byte(`{"version":1,"name":"ok","count":42,"note":null,"items":["a","b"],"rawCtx":["https://www.w3.org/ns/credentials/v2"]}`)
	var out sampleStruct
	require.NoError(t, protocol.DecodeStrictJSON(valid, &out))
	assert.Equal(t, int64(1), out.Version)
	assert.Equal(t, "ok", out.Name)
	assert.Equal(t, int64(42), out.Count)
	assert.Nil(t, out.Note)
	assert.Equal(t, []string{"a", "b"}, out.Items)
	assert.Equal(t, `["https://www.w3.org/ns/credentials/v2"]`, string(out.RawCtx))

	// Non-null pointer and optional fields populated.
	validWithNote := []byte(`{"version":2,"name":"ok","count":-9007199254740991,"small":9007199254740991,"note":"hi","optFlag":true,"items":[]}`)
	var out2 sampleStruct
	require.NoError(t, protocol.DecodeStrictJSON(validWithNote, &out2))
	require.NotNil(t, out2.Note)
	assert.Equal(t, "hi", *out2.Note)
	assert.True(t, out2.OptFlag)
	assert.Equal(t, uint64(protocol.MaxSafeInt), out2.Small)
	assert.Empty(t, out2.Items)

	badPayloads := []struct {
		name string
		raw  string
	}{
		{"unknown field", `{"version":1,"name":"ok","count":1,"note":null,"items":["a"],"extra":1}`},
		{"missing required field", `{"version":1,"name":"ok","count":1,"note":null}`},
		{"missing required nullable pointer field", `{"version":1,"name":"ok","count":1,"items":["a"]}`},
		{"null on non-nullable string", `{"version":1,"name":null,"count":1,"note":null,"items":["a"]}`},
		{"null on optional non-nullable bool", `{"version":1,"name":"ok","count":1,"note":null,"optFlag":null,"items":["a"]}`},
		{"float literal on int64 field", `{"version":1,"name":"ok","count":1.0,"note":null,"items":["a"]}`},
		{"exponent literal on int64 field", `{"version":1,"name":"ok","count":1e2,"note":null,"items":["a"]}`},
		{"negative on uint64 field", `{"version":1,"name":"ok","count":1,"small":-1,"note":null,"items":["a"]}`},
		{"not an object", `["a"]`},
	}
	for _, tc := range badPayloads {
		t.Run(tc.name, func(t *testing.T) {
			var s sampleStruct
			err := protocol.DecodeStrictJSON([]byte(tc.raw), &s)
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)
		})
	}

	// Non-pointer or nil target rejected.
	err := protocol.DecodeStrictJSON(valid, out)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))

	var nilPtr *sampleStruct
	err = protocol.DecodeStrictJSON(valid, nilPtr)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
}

func TestStringSetAndHexDigest(t *testing.T) {
	require.NoError(t, protocol.ValidateStringSet([]string{"order.create", "quote.read"}, 32))
	// UTF-16 ordering: U+10000 before U+E000.
	require.NoError(t, protocol.ValidateStringSet([]string{"\U00010000", "\uE000"}, 32))

	sorted, err := protocol.CanonicalStringSet([]string{"\uE000", "quote.read", "\U00010000"}, 32)
	require.NoError(t, err)
	assert.Equal(t, []string{"quote.read", "\U00010000", "\uE000"}, sorted)

	badSets := []struct {
		name   string
		values []string
		max    int
	}{
		{"empty", nil, 32},
		{"wildcard", []string{"*"}, 32},
		{"partial wildcard", []string{"order.*"}, 32},
		{"duplicate", []string{"a", "a"}, 32},
		{"unsorted", []string{"b", "a"}, 32},
		{"empty element", []string{""}, 32},
		{"invalid utf8", []string{string([]byte{0xff})}, 32},
		{"exceeds max", []string{"a", "b", "c"}, 2},
	}
	for _, tc := range badSets {
		t.Run(tc.name, func(t *testing.T) {
			err := protocol.ValidateStringSet(tc.values, tc.max)
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema))
		})
	}

	zero := strings.Repeat("0", 64)
	validHex := strings.Repeat("a", 64)
	assert.False(t, protocol.IsHexDigest(zero, false))
	assert.True(t, protocol.IsHexDigest(zero, true))
	assert.True(t, protocol.IsHexDigest(validHex, false))
	assert.False(t, protocol.IsHexDigest(strings.ToUpper(validHex), false))
	assert.False(t, protocol.IsHexDigest(validHex[:63], false))
}

func TestCanonicalResourceAndErrorSingleSourceOfTruth(t *testing.T) {
	require.NoError(t, protocol.ValidateCanonicalResource(protocol.ActionQuoteRead, protocol.ResourceQuotes))
	require.NoError(t, protocol.ValidateCanonicalResource(protocol.ActionOrderCreate, protocol.ResourceOrders))
	assert.True(t, protocol.IsCanonicalResource(protocol.ResourceQuotes))
	assert.True(t, protocol.IsCanonicalResource(protocol.ResourceOrders))
	assert.False(t, protocol.IsCanonicalResource("quotes"))
	assert.False(t, protocol.IsCanonicalResource("urn:grad:resource:quotes"))

	rejected := []struct {
		name     string
		action   string
		resource string
	}{
		{"legacy quotes alias", protocol.ActionQuoteRead, "quotes"},
		{"legacy quotes urn without domain", protocol.ActionQuoteRead, "urn:grad:resource:quotes"},
		{"legacy orders alias", protocol.ActionOrderCreate, "orders"},
		{"legacy orders urn without domain", protocol.ActionOrderCreate, "urn:grad:resource:orders"},
		{"mismatched quote action on orders", protocol.ActionQuoteRead, protocol.ResourceOrders},
		{"mismatched order action on quotes", protocol.ActionOrderCreate, protocol.ResourceQuotes},
		{"unknown action", "quote.write", protocol.ResourceQuotes},
		{"empty resource", protocol.ActionQuoteRead, ""},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			err := protocol.ValidateCanonicalResource(tc.action, tc.resource)
			require.Error(t, err)
			assert.True(t, protocol.HasCode(err, protocol.ErrCodeInvalidSchema), "got %v", err)
		})
	}

	// Verify protocol.Error and registry.Error are identical types (alias) sharing error codes.
	cause := errors.New("boom")
	perr := protocol.WrapError(protocol.ErrCodeStateChanged, "stale", cause)
	var rerr *registry.Error
	require.True(t, errors.As(perr, &rerr))
	assert.Equal(t, registry.ErrCodeStateChanged, protocol.CodeOf(perr))
	assert.True(t, registry.HasCode(perr, protocol.ErrCodeStateChanged))
	assert.True(t, errors.Is(perr, cause))
}
