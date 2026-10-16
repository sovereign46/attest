package modelpackage

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTensorUnsignedValues(t *testing.T) {
	for _, field := range []string{"shape", "data_offsets"} {
		t.Run(field, func(t *testing.T) {
			for _, raw := range []string{"null", "{}", "[null]", "[true]", `["1"]`, "[[]]", "[-1]", "[1.0]", "[1e1]", "[18446744073709551616]", "[1,]", "[1] []", "[1] garbage"} {
				shape, offsets := "[1]", "[0,1]"
				if field == "shape" {
					shape = raw
				} else {
					offsets = raw
				}
				header := fmt.Sprintf(`{"x":{"dtype":"U8","shape":%s,"data_offsets":%s}}`, shape, offsets)
				if _, err := parseHeader([]byte(header), 1); err == nil {
					t.Fatalf("accepted invalid %s: %s", field, raw)
				}
			}
		})
	}
	for _, shape := range []string{"[]", "[1]"} {
		header := `{"x":{"dtype":"U8","shape":` + shape + `,"data_offsets":[0,1]}}`
		if _, err := parseHeader([]byte(header), 1); err != nil {
			t.Fatalf("valid scalar/shape rejected: %v", err)
		}
	}
	header := `{"x":{"dtype":"U8","shape":[0,18446744073709551615],"data_offsets":[0,0]}}`
	if _, err := parseHeader([]byte(header), 0); err != nil {
		t.Fatalf("valid uint64 dimension rejected: %v", err)
	}
}

func TestFullHeaderRejectsArraysBeforeAttackerSizedAllocation(t *testing.T) {
	// Exercise the whole parser, including Unicode/duplicate validation. An
	// earlier strictJSON pass must not walk and allocate for every array token.
	array := append([]byte("["), bytes.Repeat([]byte("1,"), 1_000_000)...)
	array[len(array)-1] = ']'
	for _, field := range []string{"shape", "data_offsets"} {
		t.Run(field, func(t *testing.T) {
			shape, offsets := []byte("[1]"), []byte("[0,1]")
			if field == "shape" {
				shape = array
			} else {
				offsets = array
			}
			header := []byte(fmt.Sprintf(`{"x":{"dtype":"U8","shape":%s,"data_offsets":%s}}`, shape, offsets))
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			values, err := parseHeader(header, 1)
			runtime.ReadMemStats(&after)
			if err == nil || values != nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("oversized %s accepted: %v", field, err)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 256<<10 {
				t.Fatalf("full parser allocated %d bytes before rejecting oversized %s", allocated, field)
			}
		})
	}
}

func TestTensorArrayLimits(t *testing.T) {
	for name, header := range map[string]string{
		"shape":   `{"x":{"dtype":"U8","shape":[` + strings.Repeat("1,", maxTensorRank) + `1],"data_offsets":[0,1]}}`,
		"offsets": `{"x":{"dtype":"U8","shape":[1],"data_offsets":[0,1,1]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseHeader([]byte(header), 1); err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("tensor array bound not applied: %v", err)
			}
		})
	}
	header := `{"x":{"dtype":"U8","shape":[` + strings.Repeat("1,", maxTensorRank-1) + `1],"data_offsets":[0,1]}}`
	if _, err := parseHeader([]byte(header), 1); err != nil {
		t.Fatalf("maximum valid tensor rank rejected: %v", err)
	}
}
