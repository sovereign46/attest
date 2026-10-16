package modelpackage

import (
	"strings"
	"testing"
)

func TestStreamingParsersStrictJSON(t *testing.T) {
	const tensor = `{"dtype":"U8","shape":[],"data_offsets":[0,1]}`
	for name, header := range map[string]string{
		"escaped tensor duplicate": `{"x":` + tensor + `,"\u0078":` + tensor + `}`,
		"escaped field duplicate":  `{"x":{"dtype":"U8","\u0064type":"U8","shape":[],"data_offsets":[0,1]}}`,
		"metadata duplicate":       `{"__metadata__":{"a":"b","\u0061":"c"},"x":` + tensor + `}`,
		"root metadata duplicate":  `{"__metadata__":{},"__metadata__":{},"x":` + tensor + `}`,
		"surrogate duplicate":      `{"\ud83d\ude00":` + tensor + `,"😀":` + tensor + `}`,
	} {
		t.Run("header/"+name, func(t *testing.T) {
			if _, err := parseHeader([]byte(header), 1); err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("duplicate accepted or not recognized: %v", err)
			}
		})
	}
	for name, index := range map[string]string{
		"root duplicate":            `{"weight_map":{"x":"model.safetensors"},"\u0077eight_map":{"y":"model.safetensors"}}`,
		"tensor duplicate":          `{"weight_map":{"x":"model.safetensors","\u0078":"model.safetensors"}}`,
		"metadata duplicate":        `{"metadata":{"total_size":1,"total_size":1},"weight_map":{"x":"model.safetensors"}}`,
		"nested metadata duplicate": `{"metadata":{"any":[{"a":null,"\u0061":true}]},"weight_map":{"x":"model.safetensors"}}`,
		"surrogate duplicate":       `{"weight_map":{"\ud83d\ude00":"model.safetensors","😀":"model.safetensors"}}`,
	} {
		t.Run("index/"+name, func(t *testing.T) {
			if _, err := parseIndex([]byte(index)); err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("duplicate accepted or not recognized: %v", err)
			}
		})
	}

	for _, kind := range []string{"header", "index"} {
		t.Run(kind, func(t *testing.T) {
			parse := func(name, tail string) error {
				if kind == "header" {
					_, err := parseHeader([]byte(`{"`+name+`":`+tensor+`}`+tail), 1)
					return err
				}
				_, err := parseIndex([]byte(`{"weight_map":{"` + name + `":"model.safetensors"}}` + tail))
				return err
			}
			for _, name := range []string{"x", "日本語", "😀", `\ud83d\ude00`, `literal\\ud800`} {
				if err := parse(name, " \t\r\n"); err != nil {
					t.Fatalf("valid Unicode/whitespace rejected (%s): %v", name, err)
				}
			}
			for _, name := range []string{"\xff", `\ud800`, `\udc00`, `\ud800\u0061`, `\u12`, `\uZZZZ`, "raw\nnewline"} {
				if err := parse(name, ""); err == nil {
					t.Fatalf("invalid Unicode/escape accepted: %q", name)
				}
			}
			for _, tail := range []string{"{}", "[]", "null", "0", "garbage", "]"} {
				if err := parse("x", tail); err == nil {
					t.Fatalf("trailing JSON accepted: %q", tail)
				}
			}
		})
	}
}

func TestStreamingIndexMetadata(t *testing.T) {
	const weights = `"weight_map":{"x":"model.safetensors"}`
	for _, metadata := range []string{
		`{}`, `{"total_size":0}`, `{"total_size":18446744073709551615}`,
		`{"null":null,"bool":true,"string":"text","number":1e1000,"array":[null,1,{}],"object":{"nested":false}}`,
	} {
		index, err := parseIndex([]byte(`{` + weights + `,"metadata":` + metadata + `}`))
		if err != nil || index.weights["x"] != "model.safetensors" {
			t.Fatalf("valid metadata rejected (%s): %v", metadata, err)
		}
		if strings.Contains(metadata, "total_size") {
			want := uint64(0)
			if strings.Contains(metadata, "18446744073709551615") {
				want = ^uint64(0)
			}
			if index.totalSize == nil || *index.totalSize != want {
				t.Fatalf("total_size lost integer precision: %v", index.totalSize)
			}
		} else if index.totalSize != nil {
			t.Fatal("absent total_size became present")
		}
	}
	for _, metadata := range []string{
		`null`, `[]`, `"text"`, `{"total_size":null}`, `{"total_size":-1}`,
		`{"total_size":1.0}`, `{"total_size":1e0}`, `{"total_size":"1"}`, `{"total_size":18446744073709551616}`,
	} {
		if _, err := parseIndex([]byte(`{` + weights + `,"metadata":` + metadata + `}`)); err == nil {
			t.Fatalf("invalid metadata accepted: %s", metadata)
		}
	}
	for _, depth := range []int{126, 127} {
		data := []byte(`{` + weights + `,"metadata":{"nested":` + strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth) + `}}`)
		_, err := parseIndex(data)
		if (err == nil) != (depth == 126) {
			t.Fatalf("metadata depth %d: %v", depth, err)
		}
	}
}

func FuzzSafetensorsIndex(f *testing.F) {
	for _, data := range []string{
		`{"weight_map":{"x":"model.safetensors"}}`,
		`{"metadata":{"total_size":0,"other":[null,true,{}]},"weight_map":{"x":"model.safetensors"}}`,
		`{"weight_map":{"x":"model.safetensors","\u0078":"model.safetensors"}}`,
		`{"metadata":{"nested":{"a":1,"a":2}},"weight_map":{}}`,
	} {
		f.Add([]byte(data))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := parseIndex(data); err == nil {
			if err := strictJSON(data); err != nil {
				t.Fatalf("streaming index parser accepted invalid JSON: %v", err)
			}
		}
	})
}
