package modelpackage

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestFullParserTensorMapLimits(t *testing.T) {
	for _, kind := range []string{"header", "index"} {
		t.Run(kind, func(t *testing.T) {
			value := `{"dtype":"U8","shape":[0],"data_offsets":[0,0]}`
			prefix, suffix := "{", "}"
			if kind == "index" {
				value = `"model.safetensors"`
				prefix, suffix = `{"weight_map":{`, "}}"
			}
			parse := func(data []byte) (int, error) {
				if kind == "header" {
					values, err := parseHeader(data, 0)
					return len(values), err
				}
				index, err := parseIndex(data)
				return len(index.weights), err
			}

			// Use the real production ceiling, not a test-only parser limit.
			body := []byte(prefix)
			body = appendTensorMembers(body, maxTensors, value)
			boundary := append([]byte(nil), body...)
			if kind == "header" {
				// Metadata is not a tensor and remains allowed after the last one.
				boundary = append(boundary, `,"__metadata__":{"format":"pt"}`...)
			}
			boundary = append(boundary, suffix...)
			baseline := parserAllocation(t, func() {
				count, err := parse(boundary)
				if err != nil || count != maxTensors {
					t.Fatalf("maximum valid tensor map: count=%d, error=%v", count, err)
				}
			})

			// An excess member must be refused before reading its value, even
			// for duplicate checking. A generic JSON prepass would allocate for
			// every key in this otherwise syntactically valid excess object.
			body = append(body, `,"overflow":{`...)
			body = appendTensorMembers(body, maxTensors, "null")
			body = append(body, '}')
			body = append(body, suffix...)
			if len(body) > maxJSONBytes {
				t.Fatal("fixture exceeds the on-disk JSON byte limit")
			}
			allocated := parserAllocation(t, func() {
				count, err := parse(body)
				if err == nil || count != 0 || !strings.Contains(err.Error(), "exceeds") {
					t.Fatalf("tensor limit not enforced before excess value: count=%d, error=%v", count, err)
				}
			})
			// The accepted prefix has an unavoidable cost at this large cap.
			// Compare like-for-like; allow GC/map bookkeeping noise but not
			// allocations proportional to the million excess object members.
			if allocated > baseline+8<<20 {
				t.Fatalf("excess object allocated %d bytes; valid prefix allocated %d", allocated, baseline)
			}
			t.Logf("valid prefix: %d allocated bytes; oversized map: %d", baseline, allocated)
		})
	}
}

func TestFullParserRejectsTinyMembersBeforeCollectingMap(t *testing.T) {
	for _, kind := range []string{"header", "index"} {
		t.Run(kind, func(t *testing.T) {
			body := []byte("{")
			if kind == "index" {
				body = []byte(`{"weight_map":{`)
			}
			// A sub-100 MB input can contain far more keys than maxTensors.
			// The first invalid value must fail without collecting those keys.
			body = appendTensorMembers(body, 2*maxTensors, "{}")
			body = append(body, '}')
			if kind == "index" {
				body = append(body, '}')
			}
			allocated := parserAllocation(t, func() {
				var err error
				if kind == "header" {
					_, err = parseHeader(body, 0)
				} else {
					_, err = parseIndex(body)
				}
				if err == nil {
					t.Fatal("invalid member accepted")
				}
			})
			if allocated > 256<<10 {
				t.Fatalf("full parser allocated %d bytes before rejecting first member", allocated)
			}
		})
	}
}

func TestJSONObjectLimitBeforeKeyOrValue(t *testing.T) {
	// Once full, even a malformed excess key must not be read. Duplicate
	// keys at/below the limit are still refused, including escaped aliases.
	for _, extra := range []string{`"b":null`, `"a":null`, `"unterminated`} {
		decoder, err := jsonDecoder([]byte(`{"a":"ok",` + extra + `}`))
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		_, err = jsonObject(decoder, 1, func(string) (string, error) {
			calls++
			return jsonString(decoder)
		})
		if err == nil || !strings.Contains(err.Error(), "exceeds") || calls != 1 {
			t.Fatalf("excess entry was read: calls=%d, error=%v", calls, err)
		}
	}
	decoder, err := jsonDecoder([]byte(`{"a":"ok","\u0061":null}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = jsonObject(decoder, 2, func(string) (string, error) { return jsonString(decoder) })
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate not rejected before its value: %v", err)
	}
}

func appendTensorMembers(body []byte, count int, value string) []byte {
	for i := 0; i < count; i++ {
		if i != 0 {
			body = append(body, ',')
		}
		body = append(body, '"', 't')
		body = strconv.AppendInt(body, int64(i), 10)
		body = append(body, '"', ':')
		body = append(body, value...)
	}
	return body
}

func parserAllocation(t *testing.T, parse func()) uint64 {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	parse()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestIndexMetadataValueBudget(t *testing.T) {
	// The budget is shared by nested containers, not reset per child. No
	// generic prepass may decode the million-value tail after exhaustion.
	data := []byte(fmt.Sprintf(`{"weight_map":{"x":"model.safetensors"},"metadata":{"first":[%s0],"second":[%s0]}}`,
		strings.Repeat("0,", maxMetadataValues-2), strings.Repeat("0,", maxMetadataValues)))
	index, err := parseIndex(data)
	if err == nil || index.weights != nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("aggregate metadata budget not enforced: %v", err)
	}
}
