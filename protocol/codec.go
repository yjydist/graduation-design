package protocol

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"grad/protocol/registry"
)

const (
	// MaxJSONBytes limits strict protocol JSON payloads to 256 KiB.
	MaxJSONBytes = 256 * 1024
	// MaxJSONDepth limits JSON container nesting depth.
	MaxJSONDepth = 64

	// MaxSafeInt is 2^53 - 1 (IEEE-754 max safe integer).
	MaxSafeInt int64 = (1 << 53) - 1
	// MinSafeInt is -(2^53 - 1).
	MinSafeInt int64 = -((1 << 53) - 1)
)

// DigestBytes computes the 64-character lowercase hex SHA-256 digest of data.
func DigestBytes(data []byte) string {
	return registry.Digest(data)
}

// CompareUTF16 compares two strings lexicographically by UTF-16 code units (RFC 8785).
func CompareUTF16(a, b string) int {
	return registry.CompareUTF16(a, b)
}

// IsHexDigest reports whether s is 64 lowercase hex digits (optionally allowing all zeros).
func IsHexDigest(s string, allowZero bool) bool {
	if len(s) != 64 {
		return false
	}
	nonZero := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '1' && c <= '9', c >= 'a' && c <= 'f':
			nonZero = true
		case c == '0':
		default:
			return false
		}
	}
	return allowZero || nonZero
}

// ValidateStringSet checks non-emptiness, max cardinality, valid UTF-8, non-empty items,
// absence of '*' wildcards, uniqueness, and strict ascending UTF-16 code-unit order.
func ValidateStringSet(values []string, maxLen int) error {
	return validateStringSet(values, maxLen, true)
}

// CanonicalStringSet validates values as a non-empty, wildcard-free, duplicate-free set
// within maxLen and returns a copy sorted in ascending UTF-16 code-unit order.
func CanonicalStringSet(values []string, maxLen int) ([]string, error) {
	if err := validateStringSet(values, maxLen, false); err != nil {
		return nil, err
	}
	out := slices.Clone(values)
	slices.SortFunc(out, CompareUTF16)
	return out, nil
}

func validateStringSet(values []string, maxLen int, requireSorted bool) error {
	if len(values) == 0 {
		return NewError(ErrCodeInvalidSchema, "string set must not be empty")
	}
	if maxLen > 0 && len(values) > maxLen {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("string set size %d exceeds maximum %d", len(values), maxLen))
	}
	seen := make(map[string]struct{}, len(values))
	for i, s := range values {
		if s == "" || !utf8.ValidString(s) {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("string set contains empty or invalid UTF-8 item at index %d", i))
		}
		if strings.ContainsRune(s, '*') {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("string set contains forbidden wildcard %q", s))
		}
		if _, dup := seen[s]; dup {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("string set contains duplicate value %q", s))
		}
		seen[s] = struct{}{}
		if requireSorted && i > 0 && CompareUTF16(values[i-1], s) >= 0 {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("string set is not sorted ascending at index %d (%q >= %q)", i, values[i-1], s))
		}
	}
	return nil
}

// CanonicalizeJSON strictly validates raw JSON under grad-auth-v1 rules and emits RFC 8785 JCS bytes.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	if err := validateStrictJSON(raw); err != nil {
		return nil, err
	}
	val := jsontext.Value(bytes.Clone(raw))
	if err := val.Canonicalize(); err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "canonicalize JSON (RFC 8785)", err)
	}
	return []byte(val), nil
}

// DigestJCS strictly validates and canonicalizes raw JSON via RFC 8785 JCS and returns SHA-256 lowercase hex.
func DigestJCS(raw []byte) (string, error) {
	canon, err := CanonicalizeJSON(raw)
	if err != nil {
		return "", err
	}
	return DigestBytes(canon), nil
}

// MarshalJCS marshals v without HTML escaping and canonicalizes the result via RFC 8785 JCS.
func MarshalJCS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "marshal value for JCS", err)
	}
	raw := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return CanonicalizeJSON(raw)
}

// DigestValueJCS marshals v via MarshalJCS and returns its SHA-256 lowercase hex digest.
func DigestValueJCS(v any) (string, error) {
	canon, err := MarshalJCS(v)
	if err != nil {
		return "", err
	}
	return DigestBytes(canon), nil
}

// validateStrictJSON enforces grad-auth-v1 strict JSON rules using Go 1.27 encoding/json/jsontext:
// - payload size <= MaxJSONBytes (ErrCodePayloadTooLarge)
// - valid UTF-8 and valid paired UTF-16 surrogates (RFC 7493)
// - no duplicate object keys at any nesting level
// - nesting depth <= MaxJSONDepth
// - finite numbers within [MinSafeInt, MaxSafeInt]
// - single top-level JSON value with no trailing data
func validateStrictJSON(raw []byte) error {
	if len(raw) == 0 {
		return NewError(ErrCodeInvalidSchema, "empty JSON input")
	}
	if len(raw) > MaxJSONBytes {
		return NewError(ErrCodePayloadTooLarge, fmt.Sprintf("JSON input size %d exceeds %d bytes", len(raw), MaxJSONBytes))
	}
	if !utf8.Valid(raw) {
		return NewError(ErrCodeInvalidSchema, "JSON input is not valid UTF-8")
	}

	type frame struct {
		isObj     bool
		expectKey bool
		keys      map[string]struct{}
	}

	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	var (
		hasValue bool
		frames   []frame
	)
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return WrapError(ErrCodeInvalidSchema, "invalid JSON syntax", err)
		}
		if hasValue {
			return NewError(ErrCodeInvalidSchema, "trailing JSON token after top-level value")
		}

		kind := tok.Kind()
		if kind == '}' || kind == ']' {
			if len(frames) == 0 {
				return NewError(ErrCodeInvalidSchema, "unexpected closing delimiter")
			}
			frames = frames[:len(frames)-1]
			if len(frames) == 0 {
				hasValue = true
			}
			continue
		}

		if n := len(frames); n > 0 && frames[n-1].isObj && frames[n-1].expectKey {
			if kind != '"' {
				return NewError(ErrCodeInvalidSchema, "expected object key string")
			}
			key := tok.String()
			if _, dup := frames[n-1].keys[key]; dup {
				return NewError(ErrCodeInvalidSchema, fmt.Sprintf("duplicate object key %q", key))
			}
			frames[n-1].keys[key] = struct{}{}
			frames[n-1].expectKey = false
			continue
		}

		if n := len(frames); n > 0 && frames[n-1].isObj {
			frames[n-1].expectKey = true
		}

		switch kind {
		case '{':
			if len(frames) >= MaxJSONDepth {
				return NewError(ErrCodeInvalidSchema, fmt.Sprintf("JSON nesting depth exceeds limit %d", MaxJSONDepth))
			}
			frames = append(frames, frame{
				isObj:     true,
				expectKey: true,
				keys:      make(map[string]struct{}),
			})
		case '[':
			if len(frames) >= MaxJSONDepth {
				return NewError(ErrCodeInvalidSchema, fmt.Sprintf("JSON nesting depth exceeds limit %d", MaxJSONDepth))
			}
			frames = append(frames, frame{isObj: false})
		case '0':
			if err := validateNumberToken(tok.String()); err != nil {
				return err
			}
		}

		if len(frames) == 0 {
			hasValue = true
		}
	}
	if !hasValue {
		return NewError(ErrCodeInvalidSchema, "empty JSON input")
	}
	return nil
}

func validateNumberToken(raw string) error {
	if isIntegerLiteral(raw) {
		iv, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || iv < MinSafeInt || iv > MaxSafeInt {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("integer %s outside safe range [-(2^53-1), 2^53-1]", raw))
		}
		return nil
	}
	fv, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("number %q is non-finite or overflows float64", raw))
	}
	if math.Abs(fv) > float64(MaxSafeInt) {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("number %q exceeds safe magnitude 2^53-1", raw))
	}
	return nil
}

func isIntegerLiteral(raw string) bool {
	return !strings.ContainsAny(raw, ".eE")
}

// DecodeStrictJSON validates raw JSON under grad-auth-v1 rules and decodes it strictly into dst.
// It rejects oversized inputs (>256 KiB), duplicate keys, unknown fields, type mismatches,
// float literals for integer fields, null for non-pointer fields, and missing required fields
// (non-optional struct fields without "omitempty" or "optional" json tag options).
func DecodeStrictJSON(raw []byte, dst any) error {
	if err := validateStrictJSON(raw); err != nil {
		return err
	}
	rv := reflect.ValueOf(dst)
	if !rv.IsValid() || rv.Kind() != reflect.Ptr || rv.IsNil() {
		return NewError(ErrCodeInvalidSchema, "DecodeStrictJSON target must be a non-nil pointer")
	}
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	return decodeInto(dec, rv.Elem(), "")
}

var (
	jsontextValueType = reflect.TypeOf(jsontext.Value(nil))
	rawMessageType    = reflect.TypeOf(json.RawMessage(nil))
)

func decodeInto(dec *jsontext.Decoder, rv reflect.Value, path string) error {
	kind := dec.PeekKind()
	if rv.Kind() == reflect.Ptr {
		if kind == 'n' {
			if _, err := dec.ReadToken(); err != nil {
				return WrapError(ErrCodeInvalidSchema, "read null token", err)
			}
			rv.Set(reflect.Zero(rv.Type()))
			return nil
		}
		elem := reflect.New(rv.Type().Elem())
		if err := decodeInto(dec, elem.Elem(), path); err != nil {
			return err
		}
		rv.Set(elem)
		return nil
	}
	if kind == 'n' {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("null not allowed for non-nullable field %s", pathOrRoot(path)))
	}

	if rv.Type() == jsontextValueType || rv.Type() == rawMessageType {
		val, err := dec.ReadValue()
		if err != nil {
			return WrapError(ErrCodeInvalidSchema, fmt.Sprintf("read raw JSON value at %s", pathOrRoot(path)), err)
		}
		cloned := bytes.Clone(val)
		if rv.Type() == jsontextValueType {
			rv.Set(reflect.ValueOf(jsontext.Value(cloned)))
		} else {
			rv.Set(reflect.ValueOf(json.RawMessage(cloned)))
		}
		return nil
	}

	switch rv.Kind() {
	case reflect.String:
		if kind != '"' {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected string", pathOrRoot(path)))
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return WrapError(ErrCodeInvalidSchema, "read string token", err)
		}
		rv.SetString(tok.String())
		return nil

	case reflect.Bool:
		if kind != 't' && kind != 'f' {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected boolean", pathOrRoot(path)))
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return WrapError(ErrCodeInvalidSchema, "read bool token", err)
		}
		rv.SetBool(tok.Bool())
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if kind != '0' {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected safe integer", pathOrRoot(path)))
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return WrapError(ErrCodeInvalidSchema, "read integer token", err)
		}
		raw := tok.String()
		if !isIntegerLiteral(raw) {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected integer literal, got %q", pathOrRoot(path), raw))
		}
		iv, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || iv < MinSafeInt || iv > MaxSafeInt || rv.OverflowInt(iv) {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s integer %q out of range", pathOrRoot(path), raw))
		}
		rv.SetInt(iv)
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if kind != '0' {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected non-negative safe integer", pathOrRoot(path)))
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return WrapError(ErrCodeInvalidSchema, "read unsigned integer token", err)
		}
		raw := tok.String()
		if !isIntegerLiteral(raw) {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected integer literal, got %q", pathOrRoot(path), raw))
		}
		iv, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || iv < 0 || iv > MaxSafeInt || rv.OverflowUint(uint64(iv)) {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s unsigned integer %q out of range", pathOrRoot(path), raw))
		}
		rv.SetUint(uint64(iv))
		return nil

	case reflect.Float64:
		if kind != '0' {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected number", pathOrRoot(path)))
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return WrapError(ErrCodeInvalidSchema, "read float token", err)
		}
		fv, err := strconv.ParseFloat(tok.String(), 64)
		if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) || math.Abs(fv) > float64(MaxSafeInt) {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s number out of safe range", pathOrRoot(path)))
		}
		rv.SetFloat(fv)
		return nil

	case reflect.Slice:
		if kind != '[' {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected array", pathOrRoot(path)))
		}
		if _, err := dec.ReadToken(); err != nil {
			return WrapError(ErrCodeInvalidSchema, "read array start", err)
		}
		slice := reflect.MakeSlice(rv.Type(), 0, 0)
		for i := 0; dec.PeekKind() != ']'; i++ {
			elem := reflect.New(rv.Type().Elem()).Elem()
			elemPath := fmt.Sprintf("%s[%d]", pathOrRoot(path), i)
			if err := decodeInto(dec, elem, elemPath); err != nil {
				return err
			}
			slice = reflect.Append(slice, elem)
		}
		if _, err := dec.ReadToken(); err != nil {
			return WrapError(ErrCodeInvalidSchema, "read array end", err)
		}
		rv.Set(slice)
		return nil

	case reflect.Struct:
		if kind != '{' {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected object", pathOrRoot(path)))
		}
		return decodeStruct(dec, rv, path)

	case reflect.Map:
		if kind != '{' {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("field %s expected object map", pathOrRoot(path)))
		}
		if rv.Type().Key().Kind() != reflect.String {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported map key type at %s", pathOrRoot(path)))
		}
		if _, err := dec.ReadToken(); err != nil {
			return WrapError(ErrCodeInvalidSchema, "read map start", err)
		}
		m := reflect.MakeMap(rv.Type())
		for dec.PeekKind() != '}' {
			keyTok, err := dec.ReadToken()
			if err != nil {
				return WrapError(ErrCodeInvalidSchema, "read map key", err)
			}
			key := keyTok.String()
			elem := reflect.New(rv.Type().Elem()).Elem()
			if err := decodeInto(dec, elem, joinPath(path, key)); err != nil {
				return err
			}
			m.SetMapIndex(reflect.ValueOf(key), elem)
		}
		if _, err := dec.ReadToken(); err != nil {
			return WrapError(ErrCodeInvalidSchema, "read map end", err)
		}
		rv.Set(m)
		return nil

	case reflect.Interface:
		if rv.NumMethod() != 0 {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported interface target %s at %s", rv.Type(), pathOrRoot(path)))
		}
		v, err := decodeGeneric(dec)
		if err != nil {
			return err
		}
		if v != nil {
			rv.Set(reflect.ValueOf(v))
		}
		return nil

	default:
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported target type %s at %s", rv.Type(), pathOrRoot(path)))
	}
}

type structFieldInfo struct {
	index    []int
	name     string
	optional bool
}

func collectStructFields(t reflect.Type, prefix []int, byName map[string]structFieldInfo, ordered *[]structFieldInfo) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		idx := append(slices.Clone(prefix), i)
		tag := f.Tag.Get("json")
		if f.Anonymous && f.Type.Kind() == reflect.Struct && tag == "" {
			collectStructFields(f.Type, idx, byName, ordered)
			continue
		}
		if !f.IsExported() || tag == "-" {
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
		info := structFieldInfo{index: idx, name: name, optional: opt}
		byName[name] = info
		*ordered = append(*ordered, info)
	}
}

func decodeStruct(dec *jsontext.Decoder, rv reflect.Value, path string) error {
	if _, err := dec.ReadToken(); err != nil {
		return WrapError(ErrCodeInvalidSchema, "read object start", err)
	}
	byName := make(map[string]structFieldInfo)
	var ordered []structFieldInfo
	collectStructFields(rv.Type(), nil, byName, &ordered)

	seen := make(map[string]struct{}, len(ordered))
	for dec.PeekKind() != '}' {
		keyTok, err := dec.ReadToken()
		if err != nil {
			return WrapError(ErrCodeInvalidSchema, "read object key", err)
		}
		key := keyTok.String()
		info, ok := byName[key]
		if !ok {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("unknown field %q at %s", key, pathOrRoot(path)))
		}
		seen[key] = struct{}{}
		if err := decodeInto(dec, rv.FieldByIndex(info.index), joinPath(path, key)); err != nil {
			return err
		}
	}
	if _, err := dec.ReadToken(); err != nil {
		return WrapError(ErrCodeInvalidSchema, "read object end", err)
	}
	for _, info := range ordered {
		if !info.optional {
			if _, ok := seen[info.name]; !ok {
				return NewError(ErrCodeInvalidSchema, fmt.Sprintf("missing required field %q at %s", info.name, pathOrRoot(path)))
			}
		}
	}
	return nil
}

func decodeGeneric(dec *jsontext.Decoder) (any, error) {
	switch dec.PeekKind() {
	case 'n':
		_, err := dec.ReadToken()
		return nil, err
	case 't', 'f':
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		return tok.Bool(), nil
	case '"':
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		return tok.String(), nil
	case '0':
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		raw := tok.String()
		if isIntegerLiteral(raw) {
			return strconv.ParseInt(raw, 10, 64)
		}
		return strconv.ParseFloat(raw, 64)
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		out := make([]any, 0)
		for dec.PeekKind() != ']' {
			v, err := decodeGeneric(dec)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return out, nil
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		out := make(map[string]any)
		for dec.PeekKind() != '}' {
			k, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			key := k.String()
			v, err := decodeGeneric(dec)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, NewError(ErrCodeInvalidSchema, "unexpected JSON token kind")
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
