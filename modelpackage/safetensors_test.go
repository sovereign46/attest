package modelpackage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafetensorsDtypes(t *testing.T) {
	for dtype, bits := range map[string]int{
		"F4": 4, "F6_E2M3": 6, "F6_E3M2": 6, "BOOL": 8, "U8": 8, "I8": 8, "F8_E5M2": 8, "F8_E4M3": 8, "F8_E8M0": 8, "F8_E4M3FNUZ": 8, "F8_E5M2FNUZ": 8,
		"I16": 16, "U16": 16, "F16": 16, "BF16": 16, "I32": 32, "U32": 32, "F32": 32, "I64": 64, "U64": 64, "F64": 64, "C64": 64,
	} {
		t.Run(dtype, func(t *testing.T) {
			header := fmt.Sprintf(`{"x":{"dtype":%q,"shape":[8],"data_offsets":[0,%d]}}`, dtype, bits)
			data := safetensors(header, make([]byte, bits))
			tensors, n, err := readSafetensors(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if n != int64(len(data)) || tensors["x"] != uint64(bits) {
				t.Fatal("incorrect tensor size")
			}
		})
	}
}

func TestScalarAndEmptyTensors(t *testing.T) {
	data := safetensors(`{"zero":{"dtype":"BF16","shape":[0,10],"data_offsets":[0,0]},"scalar":{"dtype":"F32","shape":[],"data_offsets":[0,4]},"end":{"dtype":"I64","shape":[0],"data_offsets":[4,4]}}`, make([]byte, 4))
	if _, _, err := readSafetensors(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedSafetensors(t *testing.T) {
	valid := `{"x":{"dtype":"BF16","shape":[2],"data_offsets":[0,4]}}`
	headers := map[string]string{
		"unknown dtype":       strings.ReplaceAll(valid, "BF16", "F128"),
		"wrong shape":         strings.ReplaceAll(valid, "[2]", "[3]"),
		"null shape":          strings.ReplaceAll(valid, "[2]", "null"),
		"null dimension":      strings.ReplaceAll(valid, "[2]", "[null]"),
		"negative dimension":  strings.ReplaceAll(valid, "[2]", "[-2]"),
		"fraction dimension":  strings.ReplaceAll(valid, "[2]", "[2.0]"),
		"shape overflow":      strings.ReplaceAll(valid, "[2]", "[18446744073709551615,2]"),
		"bit size overflow":   strings.ReplaceAll(valid, "[2]", "[18446744073709551615]"),
		"negative offset":     strings.ReplaceAll(valid, "[0,4]", "[-1,3]"),
		"null offset":         strings.ReplaceAll(valid, "[0,4]", "[null,4]"),
		"too many offsets":    strings.ReplaceAll(valid, "[0,4]", "[0,4,4]"),
		"too few offsets":     strings.ReplaceAll(valid, "[0,4]", "[0]"),
		"bounds":              strings.ReplaceAll(valid, "[0,4]", "[1,5]"),
		"reversed":            strings.ReplaceAll(valid, "[0,4]", "[4,0]"),
		"hole":                `{"x":{"dtype":"BF16","shape":[1],"data_offsets":[2,4]}}`,
		"trailing bytes":      `{"x":{"dtype":"BF16","shape":[1],"data_offsets":[0,2]}}`,
		"overlap":             `{"x":{"dtype":"BF16","shape":[2],"data_offsets":[0,4]},"y":{"dtype":"BF16","shape":[1],"data_offsets":[2,4]}}`,
		"duplicate tensor":    `{"x":{"dtype":"BF16","shape":[2],"data_offsets":[0,4]},"x":{"dtype":"BF16","shape":[2],"data_offsets":[0,4]}}`,
		"duplicate dtype":     `{"x":{"dtype":"BF16","dtype":"I16","shape":[2],"data_offsets":[0,4]}}`,
		"unknown field":       `{"x":{"dtype":"BF16","shape":[2],"data_offsets":[0,4],"extra":true}}`,
		"case alias":          strings.ReplaceAll(valid, "dtype", "Dtype"),
		"missing field":       `{"x":{"shape":[2],"data_offsets":[0,4]}}`,
		"null tensor":         `{"x":null}`,
		"empty name":          strings.ReplaceAll(valid, `"x"`, `""`),
		"null header":         `null`,
		"array header":        `[]`,
		"empty header":        `{}`,
		"invalid metadata":    `{"__metadata__":{"format":null},"x":{"dtype":"BF16","shape":[2],"data_offsets":[0,4]}}`,
		"null metadata":       `{"__metadata__":null,"x":{"dtype":"BF16","shape":[2],"data_offsets":[0,4]}}`,
		"nonstring metadata":  `{"__metadata__":{"format":4},"x":{"dtype":"BF16","shape":[2],"data_offsets":[0,4]}}`,
		"nonaligned four bit": `{"x":{"dtype":"F4","shape":[7],"data_offsets":[0,4]}}`,
		"nonaligned six bit":  `{"x":{"dtype":"F6_E2M3","shape":[5],"data_offsets":[0,4]}}`,
		"leading whitespace":  " " + valid,
		"trailing JSON":       valid + "{}",
	}
	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			data := safetensors(header, make([]byte, 4))
			if _, _, err := readSafetensors(bytes.NewReader(data), int64(len(data))); err == nil {
				t.Fatal("malformed safetensors accepted")
			}
		})
	}
	for _, length := range []uint64{0, 1, maxJSONBytes + 1, ^uint64(0)} {
		t.Run(fmt.Sprintf("header length %d", length), func(t *testing.T) {
			data := safetensors(valid, make([]byte, 4))
			binary.LittleEndian.PutUint64(data[:8], length)
			if _, _, err := readSafetensors(bytes.NewReader(data), int64(len(data))); err == nil {
				t.Fatal("invalid header length accepted")
			}
		})
	}
	data := safetensors(valid, make([]byte, 4))
	for _, count := range []int{0, 7, 9, len(data) - 1} {
		if _, _, err := readSafetensors(bytes.NewReader(data[:count]), int64(len(data))); err == nil {
			t.Fatalf("truncated file (%d bytes) accepted", count)
		}
	}
}

func TestIndexClosure(t *testing.T) {
	for name, index := range map[string]string{
		"missing shard":        `{"weight_map":{"weight":"missing.safetensors","scale":"model-00002-of-00002.safetensors","quant":"model-00002-of-00002.safetensors"}}`,
		"omitted shard":        `{"weight_map":{"weight":"model-00001-of-00002.safetensors"}}`,
		"extra index tensor":   `{"weight_map":{"weight":"model-00001-of-00002.safetensors","scale":"model-00002-of-00002.safetensors","quant":"model-00002-of-00002.safetensors","extra":"model-00002-of-00002.safetensors"}}`,
		"missing index tensor": `{"weight_map":{"weight":"model-00001-of-00002.safetensors","scale":"model-00002-of-00002.safetensors"}}`,
		"wrong shard":          `{"weight_map":{"weight":"model-00002-of-00002.safetensors","scale":"model-00002-of-00002.safetensors","quant":"model-00002-of-00002.safetensors"}}`,
		"traversal":            `{"weight_map":{"weight":"../model.safetensors"}}`,
		"absolute":             `{"weight_map":{"weight":"/model.safetensors"}}`,
		"URL":                  `{"weight_map":{"weight":"https://example.test/model.safetensors"}}`,
		"pickle":               `{"weight_map":{"weight":"model.bin"}}`,
		"duplicate name":       `{"weight_map":{"weight":"model-00001-of-00002.safetensors","weight":"model-00002-of-00002.safetensors"}}`,
		"null map":             `{"weight_map":null}`,
		"empty map":            `{"weight_map":{}}`,
		"null shard":           `{"weight_map":{"weight":null}}`,
		"case alias":           `{"Weight_map":{"weight":"model-00001-of-00002.safetensors"}}`,
		"wrong total":          `{"metadata":{"total_size":7},"weight_map":{"weight":"model-00001-of-00002.safetensors","scale":"model-00002-of-00002.safetensors","quant":"model-00002-of-00002.safetensors"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			root := fixture(t)
			write(t, filepath.Join(root, "model.safetensors.index.json"), []byte(index))
			if _, err := Build(root); err == nil {
				t.Fatal("invalid index accepted")
			}
		})
	}
	t.Run("extra physical shard", func(t *testing.T) {
		root := fixture(t)
		data, err := os.ReadFile(filepath.Join(root, "model-00001-of-00002.safetensors"))
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(root, "extra.safetensors"), data)
		if _, err := Build(root); err == nil {
			t.Fatal("extra shard accepted")
		}
	})
	t.Run("missing physical shard", func(t *testing.T) {
		root := fixture(t)
		if err := os.Remove(filepath.Join(root, "model-00001-of-00002.safetensors")); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(root); err == nil {
			t.Fatal("missing shard accepted")
		}
	})
}

func FuzzSafetensorsHeader(f *testing.F) {
	f.Add([]byte(`{"x":{"dtype":"F8_E8M0","shape":[2],"data_offsets":[0,2]}}`), uint64(2))
	f.Add([]byte(`{"__metadata__":null}`), uint64(0))
	f.Fuzz(func(t *testing.T, header []byte, size uint64) {
		if _, err := parseHeader(header, size); err == nil {
			if err := strictJSON(header); err != nil {
				t.Fatalf("streaming header parser accepted invalid JSON: %v", err)
			}
		}
	})
}
