package attest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxJSONDepth           = 128
	maxJSONBytes           = 16 << 20
	maxJSONCollectionItems = 4096
)

var timeType = reflect.TypeOf(time.Time{})

// validateStrictJSON rejects representations that encoding/json would otherwise
// normalize while decoding. In particular, duplicate object members and
// case-aliased struct fields must not give different parsers different views of
// signed or trusted data. Input and collection bounds are checked before the
// typed decoder can allocate attacker-selected slices or maps.
func validateStrictJSON(data []byte, target any) error {
	if len(data) > maxJSONBytes {
		return fmt.Errorf("JSON exceeds %d-byte limit", maxJSONBytes)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8 in JSON")
	}
	if err := validateJSONEscapes(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0, reflect.TypeOf(target)); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth int, expected reflect.Type) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	expected = dereferenceJSONType(expected)
	switch delimiter {
	case '{':
		fields := jsonStructFields(expected)
		var valueType reflect.Type
		if expected != nil && expected.Kind() == reflect.Map && expected.Key().Kind() == reflect.String {
			valueType = expected.Elem()
		}
		seen := make(map[string]struct{})
		limit := jsonCollectionLimit(expected)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if len(seen) > limit {
				if expected == reflect.TypeOf(map[string]string(nil)) {
					return fmt.Errorf("subject contains too many digests: %d > %d", len(seen), limit)
				}
				return fmt.Errorf("JSON object exceeds %d-member limit", limit)
			}
			childType := valueType
			if fields != nil {
				var exists bool
				childType, exists = fields[key]
				if !exists {
					if canonical := caseFoldedJSONField(fields, key); canonical != "" {
						return fmt.Errorf("JSON field %q must use exact spelling %q", key, canonical)
					}
					return fmt.Errorf("unknown JSON field %q", key)
				}
			}
			if err := validateJSONValue(decoder, depth+1, childType); err != nil {
				return err
			}
		}
	case '[':
		var elementType reflect.Type
		if expected != nil && (expected.Kind() == reflect.Slice || expected.Kind() == reflect.Array) {
			elementType = expected.Elem()
		}
		limit := jsonCollectionLimit(expected)
		count := 0
		for decoder.More() {
			count++
			if count > limit {
				if expected == reflect.TypeOf([]ResourceDescriptor(nil)) {
					return fmt.Errorf("statement contains too many subjects: %d > %d", count, limit)
				}
				return fmt.Errorf("JSON array exceeds %d-item limit", limit)
			}
			if err := validateJSONValue(decoder, depth+1, elementType); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func dereferenceJSONType(value reflect.Type) reflect.Type {
	for value != nil && value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	return value
}

func jsonStructFields(value reflect.Type) map[string]reflect.Type {
	if value == nil || value.Kind() != reflect.Struct || value == timeType {
		return nil
	}
	fields := make(map[string]reflect.Type, value.NumField())
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func caseFoldedJSONField(fields map[string]reflect.Type, key string) string {
	for canonical := range fields {
		if strings.EqualFold(canonical, key) {
			return canonical
		}
	}
	return ""
}

func jsonCollectionLimit(value reflect.Type) int {
	value = dereferenceJSONType(value)
	if value == reflect.TypeOf([]ResourceDescriptor(nil)) {
		return MaxStatementSubjects
	}
	if value == reflect.TypeOf(map[string]string(nil)) {
		return MaxSubjectDigests
	}
	return maxJSONCollectionItems
}

// encoding/json replaces unpaired UTF-16 surrogate escapes with U+FFFD. Reject
// them rather than validating or signing a normalized value different from the
// encoded member name or string.
func validateJSONEscapes(data []byte) error {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) || data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return fmt.Errorf("incomplete JSON Unicode escape")
		}
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return err
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return fmt.Errorf("unpaired JSON low surrogate")
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return fmt.Errorf("unpaired JSON high surrogate")
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("invalid JSON surrogate pair")
			}
			i += 6
		}
	}
	return nil
}
