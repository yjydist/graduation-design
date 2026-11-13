package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// MaxJSONBytes limits strict protocol JSON payloads to 256 KiB.
	MaxJSONBytes = 256 * 1024

	// MaxSafeInt is 2^53 - 1 (IEEE-754 max safe integer).
	MaxSafeInt int64 = (1 << 53) - 1
	// MinSafeInt is -(2^53 - 1).
	MinSafeInt int64 = -((1 << 53) - 1)

	maxJSONDepth = 64
)

// JSONKind identifies the node type in a strict parsed JSON AST.
type JSONKind int

const (
	KindNull JSONKind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

// JSONMember represents one key-value pair inside a JSON object AST.
type JSONMember struct {
	Key   string
	Value *JSONValue
}

// JSONValue is a lossless strict RFC 8259 AST node enforcing unique object keys
// and grad-auth-v1 safe number bounds.
type JSONValue struct {
	Kind         JSONKind
	BoolVal      bool
	StrVal       string
	IntVal       int64
	FloatVal     float64
	IsIntLiteral bool
	RawNum       string
	ArrayVal     []*JSONValue
	ObjectVal    []JSONMember
	objectIndex  map[string]*JSONValue
}

// Get returns the member value for key if this node is an object and key exists.
func (v *JSONValue) Get(key string) (*JSONValue, bool) {
	if v == nil || v.Kind != KindObject {
		return nil, false
	}
	m, ok := v.objectIndex[key]
	return m, ok
}

// MarshalJSON serializes JSONValue using RFC 8785 JCS so typed Go structs embedding
// JSONValue fields round-trip cleanly without HTML escaping.
func (v JSONValue) MarshalJSON() ([]byte, error) {
	return CanonicalizeValue(&v)
}

// DigestBytes computes lowercase hex SHA-256 of raw bytes.
func DigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ParseStrictJSON parses raw UTF-8 JSON bytes according to RFC 8259 + grad-auth-v1 rules:
// - input length <= 256 KiB
// - strictly valid UTF-8 and valid paired UTF-16 surrogates
// - no duplicate object keys at any depth
// - numbers finite and within [- (2^53 - 1), 2^53 - 1]
// - no trailing tokens
func ParseStrictJSON(raw []byte) (*JSONValue, error) {
	if len(raw) == 0 {
		return nil, NewError(ErrCodeInvalidSchema, "empty JSON input")
	}
	if len(raw) > MaxJSONBytes {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("JSON input size %d exceeds %d bytes", len(raw), MaxJSONBytes))
	}
	if !utf8.Valid(raw) {
		return nil, NewError(ErrCodeInvalidSchema, "input is not valid UTF-8")
	}
	p := &strictParser{data: raw}
	p.skipWS()
	val, err := p.parseValue(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("trailing data at byte offset %d", p.pos))
	}
	return val, nil
}

// CanonicalizeJSON parses raw JSON strictly and emits its RFC 8785 JCS canonical bytes.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	val, err := ParseStrictJSON(raw)
	if err != nil {
		return nil, err
	}
	return CanonicalizeValue(val)
}

// DigestJCS parses raw JSON strictly, canonicalizes it with RFC 8785 JCS, and returns
// both the lowercase SHA-256 hex digest and the canonical JCS bytes.
func DigestJCS(raw []byte) (string, []byte, error) {
	canon, err := CanonicalizeJSON(raw)
	if err != nil {
		return "", nil, err
	}
	return DigestBytes(canon), canon, nil
}

// CanonicalizeValue serializes a parsed JSONValue using RFC 8785 JCS.
func CanonicalizeValue(val *JSONValue) ([]byte, error) {
	if val == nil {
		return nil, NewError(ErrCodeInvalidSchema, "nil JSON value")
	}
	var buf bytes.Buffer
	if err := writeJCS(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalJCS marshals a Go value without HTML escaping and canonicalizes the result via JCS.
func MarshalJCS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "marshal value for JCS", err)
	}
	raw := bytes.TrimRight(buf.Bytes(), "\n")
	return CanonicalizeJSON(raw)
}

type strictParser struct {
	data []byte
	pos  int
}

func (p *strictParser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *strictParser) parseValue(depth int) (*JSONValue, error) {
	if depth > maxJSONDepth {
		return nil, NewError(ErrCodeInvalidSchema, "JSON nesting depth exceeds limit")
	}
	if p.pos >= len(p.data) {
		return nil, NewError(ErrCodeInvalidSchema, "unexpected end of JSON input")
	}
	switch p.data[p.pos] {
	case '{':
		return p.parseObject(depth + 1)
	case '[':
		return p.parseArray(depth + 1)
	case '"':
		s, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &JSONValue{Kind: KindString, StrVal: s}, nil
	case 't':
		if bytes.HasPrefix(p.data[p.pos:], []byte("true")) {
			p.pos += 4
			return &JSONValue{Kind: KindBool, BoolVal: true}, nil
		}
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid literal at offset %d", p.pos))
	case 'f':
		if bytes.HasPrefix(p.data[p.pos:], []byte("false")) {
			p.pos += 5
			return &JSONValue{Kind: KindBool, BoolVal: false}, nil
		}
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid literal at offset %d", p.pos))
	case 'n':
		if bytes.HasPrefix(p.data[p.pos:], []byte("null")) {
			p.pos += 4
			return &JSONValue{Kind: KindNull}, nil
		}
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid literal at offset %d", p.pos))
	default:
		if p.data[p.pos] == '-' || (p.data[p.pos] >= '0' && p.data[p.pos] <= '9') {
			return p.parseNumber()
		}
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("unexpected character %q at offset %d", p.data[p.pos], p.pos))
	}
}

func (p *strictParser) parseObject(depth int) (*JSONValue, error) {
	p.pos++ // skip '{'
	p.skipWS()
	var members []JSONMember
	seen := make(map[string]*JSONValue)
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return &JSONValue{Kind: KindObject, ObjectVal: members, objectIndex: seen}, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("expected object key string at offset %d", p.pos))
		}
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if _, exists := seen[key]; exists {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("duplicate object key %q", key))
		}
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("expected ':' after key %q at offset %d", key, p.pos))
		}
		p.pos++
		p.skipWS()
		val, err := p.parseValue(depth)
		if err != nil {
			return nil, err
		}
		members = append(members, JSONMember{Key: key, Value: val})
		seen[key] = val

		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, NewError(ErrCodeInvalidSchema, "unterminated JSON object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return &JSONValue{Kind: KindObject, ObjectVal: members, objectIndex: seen}, nil
		default:
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("expected ',' or '}' in object at offset %d", p.pos))
		}
	}
}

func (p *strictParser) parseArray(depth int) (*JSONValue, error) {
	p.pos++ // skip '['
	p.skipWS()
	var items []*JSONValue
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return &JSONValue{Kind: KindArray, ArrayVal: items}, nil
	}
	for {
		p.skipWS()
		val, err := p.parseValue(depth)
		if err != nil {
			return nil, err
		}
		items = append(items, val)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, NewError(ErrCodeInvalidSchema, "unterminated JSON array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return &JSONValue{Kind: KindArray, ArrayVal: items}, nil
		default:
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("expected ',' or ']' in array at offset %d", p.pos))
		}
	}
}

func (p *strictParser) parseString() (string, error) {
	p.pos++ // skip opening '"'
	var buf bytes.Buffer
	for p.pos < len(p.data) {
		b := p.data[p.pos]
		if b == '"' {
			p.pos++
			return buf.String(), nil
		}
		if b == '\\' {
			p.pos++
			if p.pos >= len(p.data) {
				return "", NewError(ErrCodeInvalidSchema, "unterminated escape sequence in string")
			}
			esc := p.data[p.pos]
			p.pos++
			switch esc {
			case '"', '\\', '/':
				buf.WriteByte(esc)
			case 'b':
				buf.WriteByte('\b')
			case 'f':
				buf.WriteByte('\f')
			case 'n':
				buf.WriteByte('\n')
			case 'r':
				buf.WriteByte('\r')
			case 't':
				buf.WriteByte('\t')
			case 'u':
				u1, err := p.parseHex4()
				if err != nil {
					return "", err
				}
				if u1 >= 0xD800 && u1 <= 0xDBFF {
					if p.pos+2 > len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
						return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("unpaired high UTF-16 surrogate 0x%04x", u1))
					}
					p.pos += 2
					u2, err := p.parseHex4()
					if err != nil {
						return "", err
					}
					if u2 < 0xDC00 || u2 > 0xDFFF {
						return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid low UTF-16 surrogate 0x%04x after 0x%04x", u2, u1))
					}
					r := utf16.DecodeRune(rune(u1), rune(u2))
					buf.WriteRune(r)
				} else if u1 >= 0xDC00 && u1 <= 0xDFFF {
					return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("unpaired low UTF-16 surrogate 0x%04x", u1))
				} else {
					buf.WriteRune(rune(u1))
				}
			default:
				return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid escape sequence \\%c", esc))
			}
			continue
		}
		if b < 0x20 {
			return "", NewError(ErrCodeInvalidSchema, fmt.Sprintf("unescaped control character 0x%02x in string", b))
		}
		if b < utf8.RuneSelf {
			buf.WriteByte(b)
			p.pos++
			continue
		}
		r, width := utf8.DecodeRune(p.data[p.pos:])
		buf.WriteRune(r)
		p.pos += width
	}
	return "", NewError(ErrCodeInvalidSchema, "unterminated JSON string")
}

func (p *strictParser) parseHex4() (uint16, error) {
	if p.pos+4 > len(p.data) {
		return 0, NewError(ErrCodeInvalidSchema, "truncated \\uXXXX escape")
	}
	var val uint16
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			val |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			val |= uint16(c-'A') + 10
		default:
			return 0, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid hex digit %q in \\uXXXX escape", c))
		}
	}
	p.pos += 4
	return val, nil
}

func (p *strictParser) parseNumber() (*JSONValue, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.data) {
		return nil, NewError(ErrCodeInvalidSchema, "invalid number: trailing '-'")
	}
	if p.data[p.pos] == '0' {
		p.pos++
		if p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			return nil, NewError(ErrCodeInvalidSchema, "invalid number: leading zero")
		}
	} else if p.data[p.pos] >= '1' && p.data[p.pos] <= '9' {
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	} else {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid number at offset %d", start))
	}

	hasFracOrExp := false
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		hasFracOrExp = true
		p.pos++
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, NewError(ErrCodeInvalidSchema, "invalid number: expected digits after '.'")
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		hasFracOrExp = true
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, NewError(ErrCodeInvalidSchema, "invalid number: expected digits in exponent")
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}

	rawNum := string(p.data[start:p.pos])
	if !hasFracOrExp {
		bi, ok := new(big.Int).SetString(rawNum, 10)
		if !ok {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid integer %q", rawNum))
		}
		maxBig := big.NewInt(MaxSafeInt)
		minBig := big.NewInt(MinSafeInt)
		if bi.Cmp(maxBig) > 0 || bi.Cmp(minBig) < 0 {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("integer %s outside safe range [-(2^53-1), 2^53-1]", rawNum))
		}
		iv := bi.Int64()
		return &JSONValue{
			Kind:         KindNumber,
			IntVal:       iv,
			FloatVal:     float64(iv),
			IsIntLiteral: true,
			RawNum:       rawNum,
		}, nil
	}

	fv, err := strconv.ParseFloat(rawNum, 64)
	if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("number %q is non-finite or overflows float64", rawNum))
	}
	if math.Abs(fv) > float64(MaxSafeInt) {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("number %q exceeds safe magnitude 2^53-1", rawNum))
	}
	if fv == 0 {
		fv = 0 // collapse -0 to +0 per RFC 8785
	}
	return &JSONValue{
		Kind:         KindNumber,
		FloatVal:     fv,
		IsIntLiteral: false,
		RawNum:       rawNum,
	}, nil
}

func compareUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] < ub[i] {
			return -1
		}
		if ua[i] > ub[i] {
			return 1
		}
	}
	if len(ua) < len(ub) {
		return -1
	}
	if len(ua) > len(ub) {
		return 1
	}
	return 0
}

func writeJCS(buf *bytes.Buffer, v *JSONValue) error {
	switch v.Kind {
	case KindNull:
		buf.WriteString("null")
	case KindBool:
		if v.BoolVal {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case KindNumber:
		s, err := formatJCSNumber(v)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case KindString:
		writeJCSString(buf, v.StrVal)
	case KindArray:
		buf.WriteByte('[')
		for i, item := range v.ArrayVal {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCS(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case KindObject:
		sorted := make([]JSONMember, len(v.ObjectVal))
		copy(sorted, v.ObjectVal)
		sort.Slice(sorted, func(i, j int) bool {
			return compareUTF16(sorted[i].Key, sorted[j].Key) < 0
		})
		buf.WriteByte('{')
		for i, m := range sorted {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, m.Key)
			buf.WriteByte(':')
			if err := writeJCS(buf, m.Value); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return NewError(ErrCodeInvalidSchema, "unknown JSON AST node kind")
	}
	return nil
}

func writeJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		b := s[i]
		if b < utf8.RuneSelf {
			switch b {
			case '"':
				buf.WriteString(`\"`)
			case '\\':
				buf.WriteString(`\\`)
			case '\b':
				buf.WriteString(`\b`)
			case '\f':
				buf.WriteString(`\f`)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			default:
				if b < 0x20 {
					fmt.Fprintf(buf, `\u%04x`, b)
				} else {
					buf.WriteByte(b)
				}
			}
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		buf.WriteString(s[i : i+size])
		i += size
	}
	buf.WriteByte('"')
}

func formatJCSNumber(v *JSONValue) (string, error) {
	if v.IsIntLiteral {
		return strconv.FormatInt(v.IntVal, 10), nil
	}
	return formatES6Number(v.FloatVal)
}

// formatES6Number implements ECMAScript Number::toString (RFC 8785 Section 3.2.2.3)
// for finite float64 numbers within [-MaxSafeInt, MaxSafeInt].
func formatES6Number(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", NewError(ErrCodeInvalidSchema, "non-finite float in JCS")
	}
	if f == 0 {
		return "0", nil
	}
	var neg bool
	if f < 0 {
		neg = true
		f = -f
	}
	// Shortest decimal mantissa + exponent in e-notation via Ryu ('e', -1, 64).
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	eIdx := strings.IndexByte(sci, 'e')
	mant := sci[:eIdx]
	exp, err := strconv.Atoi(sci[eIdx+1:])
	if err != nil {
		return "", err
	}
	digits := strings.ReplaceAll(mant, ".", "")
	// n is number of integer digits: value = 0.<digits> * 10^n
	n := exp + 1
	k := len(digits)

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	case k == 1:
		sign := "+"
		e := n - 1
		if e < 0 {
			sign = "-"
			e = -e
		}
		out = digits + "e" + sign + strconv.Itoa(e)
	default:
		sign := "+"
		e := n - 1
		if e < 0 {
			sign = "-"
			e = -e
		}
		out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(e)
	}
	if neg {
		return "-" + out, nil
	}
	return out, nil
}

// DecodeStrictJSON parses raw UTF-8 JSON and populates dst (pointer to struct).
// It rejects duplicate keys, unknown fields, non-object roots, and type mismatches.
// Non-pointer fields must be present and non-null unless the json tag ends with ",optional".
func DecodeStrictJSON(raw []byte, dst any) error {
	val, err := ParseStrictJSON(raw)
	if err != nil {
		return err
	}
	return decodeValueInto(val, reflect.ValueOf(dst), "")
}

// DecodeStrictValue decodes a pre-parsed *JSONValue into dst (pointer to struct or value).
func DecodeStrictValue(val *JSONValue, dst any) error {
	return decodeValueInto(val, reflect.ValueOf(dst), "")
}

func decodeValueInto(val *JSONValue, rv reflect.Value, path string) error {
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return NewError(ErrCodeInvalidSchema, "DecodeStrict target must be a non-nil pointer")
	}
	return assignJSONValue(val, rv.Elem(), path)
}

func assignJSONValue(val *JSONValue, rv reflect.Value, path string) error {
	if val == nil {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("nil AST value at %s", pathOrRoot(path)))
	}
	if rv.Kind() == reflect.Ptr {
		if val.Kind == KindNull {
			rv.Set(reflect.Zero(rv.Type()))
			return nil
		}
		elem := reflect.New(rv.Type().Elem())
		if err := assignJSONValue(val, elem.Elem(), path); err != nil {
			return err
		}
		rv.Set(elem)
		return nil
	}
	if val.Kind == KindNull {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("null not allowed for non-nullable field %s", pathOrRoot(path)))
	}

	// Allow *JSONValue fields inside typed structs if needed.
	if rv.Type() == reflect.TypeOf(JSONValue{}) {
		rv.Set(reflect.ValueOf(*val))
		return nil
	}

	switch rv.Kind() {
	case reflect.String:
		if val.Kind != KindString {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected string", pathOrRoot(path)))
		}
		rv.SetString(val.StrVal)
		return nil
	case reflect.Bool:
		if val.Kind != KindBool {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected boolean", pathOrRoot(path)))
		}
		rv.SetBool(val.BoolVal)
		return nil
	case reflect.Int64, reflect.Int:
		if val.Kind != KindNumber || !val.IsIntLiteral {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected safe integer", pathOrRoot(path)))
		}
		rv.SetInt(val.IntVal)
		return nil
	case reflect.Uint64:
		if val.Kind != KindNumber || !val.IsIntLiteral || val.IntVal < 0 {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected non-negative safe integer", pathOrRoot(path)))
		}
		rv.SetUint(uint64(val.IntVal))
		return nil
	case reflect.Slice:
		if val.Kind != KindArray {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected array", pathOrRoot(path)))
		}
		slice := reflect.MakeSlice(rv.Type(), len(val.ArrayVal), len(val.ArrayVal))
		for i, item := range val.ArrayVal {
			elemPath := fmt.Sprintf("%s[%d]", pathOrRoot(path), i)
			if err := assignJSONValue(item, slice.Index(i), elemPath); err != nil {
				return err
			}
		}
		rv.Set(slice)
		return nil
	case reflect.Struct:
		if val.Kind != KindObject {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected object", pathOrRoot(path)))
		}
		return assignStruct(val, rv, path)
	case reflect.Map:
		if val.Kind != KindObject {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected object map", pathOrRoot(path)))
		}
		if rv.Type().Key().Kind() != reflect.String {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported map key type at %s", pathOrRoot(path)))
		}
		m := reflect.MakeMapWithSize(rv.Type(), len(val.ObjectVal))
		for _, member := range val.ObjectVal {
			elem := reflect.New(rv.Type().Elem()).Elem()
			subPath := joinPath(path, member.Key)
			if err := assignJSONValue(member.Value, elem, subPath); err != nil {
				return err
			}
			m.SetMapIndex(reflect.ValueOf(member.Key), elem)
		}
		rv.Set(m)
		return nil
	case reflect.Interface:
		goVal, err := toGenericValue(val)
		if err != nil {
			return err
		}
		rv.Set(reflect.ValueOf(goVal))
		return nil
	default:
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported target type %s at %s", rv.Type(), pathOrRoot(path)))
	}
}

type structFieldInfo struct {
	index    int
	name     string
	optional bool
	nullable bool
}

func assignStruct(val *JSONValue, rv reflect.Value, path string) error {
	t := rv.Type()
	fields := make(map[string]structFieldInfo)
	var ordered []structFieldInfo
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			name = f.Name
		}
		opt := false
		for _, optPart := range parts[1:] {
			if optPart == "omitempty" || optPart == "optional" {
				opt = true
			}
		}
		info := structFieldInfo{
			index:    i,
			name:     name,
			optional: opt,
			nullable: f.Type.Kind() == reflect.Ptr,
		}
		fields[name] = info
		ordered = append(ordered, info)
	}

	for _, member := range val.ObjectVal {
		info, ok := fields[member.Key]
		if !ok {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unknown field %q at %s", member.Key, pathOrRoot(path)))
		}
		if err := assignJSONValue(member.Value, rv.Field(info.index), joinPath(path, member.Key)); err != nil {
			return err
		}
	}

	for _, info := range ordered {
		if _, present := val.Get(info.name); !present {
			if !info.optional {
				return NewError(ErrCodeInvalidSchema, fmt.Sprintf("missing required field %q at %s", info.name, pathOrRoot(path)))
			}
		}
	}
	return nil
}

func toGenericValue(val *JSONValue) (any, error) {
	switch val.Kind {
	case KindNull:
		return nil, nil
	case KindBool:
		return val.BoolVal, nil
	case KindString:
		return val.StrVal, nil
	case KindNumber:
		if val.IsIntLiteral {
			return val.IntVal, nil
		}
		return val.FloatVal, nil
	case KindArray:
		out := make([]any, len(val.ArrayVal))
		for i, item := range val.ArrayVal {
			v, err := toGenericValue(item)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	case KindObject:
		out := make(map[string]any, len(val.ObjectVal))
		for _, m := range val.ObjectVal {
			v, err := toGenericValue(m.Value)
			if err != nil {
				return nil, err
			}
			out[m.Key] = v
		}
		return out, nil
	default:
		return nil, NewError(ErrCodeInvalidSchema, "unknown JSON AST kind")
	}
}

func pathOrRoot(p string) string {
	if p == "" {
		return "$"
	}
	return p
}

func joinPath(base, key string) string {
	if base == "" {
		return "$." + key
	}
	return base + "." + key
}

// ValidateStringSet checks non-emptiness, max cardinality, non-empty strings, no wildcards ("*"),
// uniqueness, and (optionally) strict ascending UTF-16 order.
func ValidateStringSet(field string, values []string, maxLen int, requireSorted bool) error {
	if len(values) == 0 {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("%s must not be empty", field))
	}
	if maxLen > 0 && len(values) > maxLen {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("%s size %d exceeds maximum %d", field, len(values), maxLen))
	}
	seen := make(map[string]struct{}, len(values))
	for i, s := range values {
		if s == "" {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("%s contains empty item at index %d", field, i))
		}
		if s == "*" || strings.ContainsRune(s, '*') {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("%s contains forbidden wildcard %q", field, s))
		}
		if _, dup := seen[s]; dup {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("%s contains duplicate value %q", field, s))
		}
		seen[s] = struct{}{}
		if requireSorted && i > 0 && compareUTF16(values[i-1], s) >= 0 {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("%s is not sorted ascending at index %d (%q >= %q)", field, i, values[i-1], s))
		}
	}
	return nil
}

// CanonicalStringSet returns a sorted, deduplicated copy or rejects invalid sets.
func CanonicalStringSet(field string, values []string, maxLen int) ([]string, error) {
	if err := ValidateStringSet(field, values, maxLen, false); err != nil {
		return nil, err
	}
	out := append([]string(nil), values...)
	sort.Slice(out, func(i, j int) bool {
		return compareUTF16(out[i], out[j]) < 0
	})
	return out, nil
}
