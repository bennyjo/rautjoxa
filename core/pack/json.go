package pack

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
)

// The reader checks every JSON member against the exact shape the format
// specifies before decoding it. encoding/json alone would accept keys in any
// case, duplicate keys, missing fields, nulls, and invalid UTF-8.

type shapeKind int

const (
	kindString     shapeKind = iota
	kindCount                // a non-negative integer
	kindTime                 // RFC 3339 UTC, with optional fractional seconds
	kindSecondTime           // RFC 3339 UTC, to the second
	kindObject               // exactly the fields in shape.fields
	kindStringMap            // any keys, string values
	kindArray                // elements of shape shape.elem
)

type shape struct {
	kind   shapeKind
	fields map[string]*shape
	elem   *shape
}

var (
	countPattern      = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	timePattern       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)
	secondTimePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

	str = &shape{kind: kindString}

	sidecarShape = &shape{kind: kindObject, fields: map[string]*shape{
		"path":      str,
		"size":      {kind: kindCount},
		"modified":  {kind: kindTime},
		"mime_type": str,
		"source": {kind: kindObject, fields: map[string]*shape{
			"id":       str,
			"key":      str,
			"metadata": {kind: kindStringMap},
		}},
	}}

	manifestShape = &shape{kind: kindObject, fields: map[string]*shape{
		"format":  str,
		"version": {kind: kindCount},
		"id":      str,
		"created": {kind: kindSecondTime},
		"writer":  str,
		"signer":  str,
		"members": {kind: kindArray, elem: &shape{kind: kindObject, fields: map[string]*shape{
			"path":   str,
			"size":   {kind: kindCount},
			"sha256": str,
		}}},
	}}
)

// checkJSON reports whether data is exactly one JSON value of shape s: valid
// UTF-8 with no unpaired surrogate escapes, no duplicate keys, every field
// present with the right type, no other fields, and nothing after the value.
func checkJSON(data []byte, s *shape) error {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	if err := checkValue(dec, s, ""); err != nil {
		return err
	}
	switch _, err := dec.ReadToken(); err {
	case io.EOF:
		return nil
	case nil:
		return errors.New("data after the JSON value")
	default:
		return err
	}
}

func checkValue(dec *jsontext.Decoder, s *shape, at string) error {
	tok, err := dec.ReadToken()
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	kind := tok.Kind()
	switch s.kind {
	case kindString, kindTime, kindSecondTime:
		if kind != '"' {
			return fmt.Errorf("%s is %v, expected a string", name(at), kind)
		}
		if s.kind == kindTime && !timePattern.MatchString(tok.String()) {
			return fmt.Errorf("%s %q is not an RFC 3339 UTC time", name(at), tok.String())
		}
		if s.kind == kindSecondTime && !secondTimePattern.MatchString(tok.String()) {
			return fmt.Errorf("%s %q is not an RFC 3339 UTC time to the second", name(at), tok.String())
		}
	case kindCount:
		if kind != '0' || !countPattern.MatchString(tok.String()) {
			return fmt.Errorf("%s %s is not a non-negative integer", name(at), tok.String())
		}
	case kindObject, kindStringMap:
		if kind != '{' {
			return fmt.Errorf("%s is %v, expected an object", name(at), kind)
		}
		seen := make(map[string]bool)
		for dec.PeekKind() != '}' {
			key, err := dec.ReadToken()
			if err != nil {
				return err
			}
			field, child := join(at, key.String()), str
			if s.kind == kindObject {
				if child = s.fields[key.String()]; child == nil {
					return fmt.Errorf("unknown field %q", field)
				}
			}
			// The decoder already rejects duplicate keys.
			seen[key.String()] = true
			if err := checkValue(dec, child, field); err != nil {
				return err
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		for _, key := range slices.Sorted(maps.Keys(s.fields)) {
			if !seen[key] {
				return fmt.Errorf("missing field %q", join(at, key))
			}
		}
	case kindArray:
		if kind != '[' {
			return fmt.Errorf("%s is %v, expected an array", name(at), kind)
		}
		for i := 0; dec.PeekKind() != ']'; i++ {
			if err := checkValue(dec, s.elem, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
	}
	return nil
}

func join(at, key string) string {
	if at == "" {
		return key
	}
	return at + "." + key
}

func name(at string) string {
	if at == "" {
		return "the JSON value"
	}
	return fmt.Sprintf("field %q", at)
}
