package modelpackage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// strictJSON rejects duplicate object keys at every nesting level, invalid
// UTF-8, excessive nesting and trailing JSON values before typed decoding.
func strictJSON(data []byte) error {
	decoder, err := jsonDecoder(data)
	if err != nil {
		return err
	}
	if err := jsonValue(decoder, 0, nil); err != nil {
		return err
	}
	return jsonEnd(decoder)
}

// Validate string encoding without collecting keys or values. Typed streaming
// parsers must enforce their own cardinality limits before reading each value.
func jsonDecoder(data []byte) (*json.Decoder, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid UTF-8 in JSON")
	}
	if err := validEscapes(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder, nil
}

func jsonEnd(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func jsonDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != want {
		return fmt.Errorf("expected JSON %q", want)
	}
	return nil
}

func jsonString(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", fmt.Errorf("expected JSON string")
	}
	return value, nil
}

// The result map doubles as the duplicate-key set. No RawMessage copy or second
// map of all keys is needed, and excess values are never read or accumulated.
func jsonObject[T any](decoder *json.Decoder, limit int, read func(string) (T, error)) (map[string]T, error) {
	if err := jsonDelimiter(decoder, '{'); err != nil {
		return nil, err
	}
	values := make(map[string]T)
	for decoder.More() {
		if len(values) == limit {
			return nil, fmt.Errorf("JSON object exceeds %d entries", limit)
		}
		key, err := jsonString(decoder)
		if err != nil {
			return nil, err
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("duplicate JSON key %q", key)
		}
		value, err := read(key)
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	if err := jsonDelimiter(decoder, '}'); err != nil {
		return nil, err
	}
	return values, nil
}

// encoding/json replaces unpaired UTF-16 surrogate escapes with U+FFFD;
// safetensors/serde rejects them. Do not hash one name and validate another.
func validEscapes(data []byte) error {
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

func jsonValue(decoder *json.Decoder, depth int, remaining *int) error {
	if remaining != nil {
		if *remaining == 0 {
			return fmt.Errorf("JSON metadata exceeds value budget")
		}
		*remaining--
	}
	if depth > 128 {
		return fmt.Errorf("JSON nesting exceeds 128")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			if remaining != nil && *remaining == 0 {
				return fmt.Errorf("JSON metadata exceeds value budget")
			}
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if keys[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = true
			if err := jsonValue(decoder, depth+1, remaining); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := jsonValue(decoder, depth+1, remaining); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
