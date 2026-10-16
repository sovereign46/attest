package modelpackage

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	maxTensors    = 1_000_000
	maxTensorRank = 128
	// Shared across all index metadata values, including nested containers.
	maxMetadataValues = maxTensors
)

type weightIndex struct {
	weights   map[string]string
	totalSize *uint64
}

func parseIndex(data []byte) (weightIndex, error) {
	var index weightIndex
	decoder, err := jsonDecoder(data)
	if err != nil {
		return index, err
	}
	_, err = jsonObject(decoder, 2, func(key string) (struct{}, error) {
		var err error
		switch key {
		case "weight_map":
			index.weights, err = jsonObject(decoder, maxTensors, func(tensor string) (string, error) {
				if tensor == "" || tensor == "__metadata__" {
					return "", fmt.Errorf("invalid index tensor name %q", tensor)
				}
				shard, err := jsonString(decoder)
				if err != nil {
					return "", err
				}
				if err := canonicalPath(shard); err != nil {
					return "", err
				}
				if strings.Contains(shard, "/") || !allowedFile(shard) || !strings.HasSuffix(shard, ".safetensors") {
					return "", fmt.Errorf("invalid index shard %q", shard)
				}
				return shard, nil
			})
		case "metadata":
			index.totalSize, err = parseIndexMetadata(decoder)
		default:
			err = fmt.Errorf("unknown index field %q", key)
		}
		return struct{}{}, err
	})
	if err != nil {
		return weightIndex{}, err
	}
	if len(index.weights) == 0 {
		return weightIndex{}, fmt.Errorf("index must contain 1..%d tensors", maxTensors)
	}
	if err := jsonEnd(decoder); err != nil {
		return weightIndex{}, err
	}
	return index, nil
}

func parseIndexMetadata(decoder *json.Decoder) (*uint64, error) {
	remaining := maxMetadataValues
	var total *uint64
	_, err := jsonObject(decoder, maxMetadataValues, func(key string) (struct{}, error) {
		if remaining == 0 {
			return struct{}{}, fmt.Errorf("JSON metadata exceeds value budget")
		}
		if key == "total_size" {
			remaining--
			value, err := jsonUnsigned(decoder)
			if err != nil {
				return struct{}{}, fmt.Errorf("index total_size: %w", err)
			}
			total = &value
			return struct{}{}, nil
		}
		// Unknown metadata remains valid JSON of any type. Bound the entire
		// nested value graph, not each object separately, and retain no values.
		return struct{}{}, jsonValue(decoder, 2, &remaining)
	})
	return total, err
}

func checkClosure(index weightIndex, shards map[string]map[string]uint64) error {
	if len(shards) == 0 {
		return fmt.Errorf("no safetensors shards")
	}
	seen := make(map[string]bool, len(index.weights))
	var total uint64
	for shard, tensors := range shards {
		for tensor, size := range tensors {
			if index.weights[tensor] != shard {
				return fmt.Errorf("tensor %q in shard %q is absent from index or mapped to another shard", tensor, shard)
			}
			if seen[tensor] {
				return fmt.Errorf("duplicate tensor %q across shards", tensor)
			}
			seen[tensor] = true
			if size > math.MaxUint64-total {
				return fmt.Errorf("total tensor size overflow")
			}
			total += size
		}
	}
	if len(seen) != len(index.weights) {
		return fmt.Errorf("index references missing shards or tensors")
	}
	if index.totalSize != nil && *index.totalSize != total {
		return fmt.Errorf("index total_size differs from tensor data size")
	}
	return nil
}

// readSafetensors follows the official format and Rust Dtype::bitsize rules:
// https://github.com/safetensors/safetensors/blob/main/safetensors/src/tensor.rs
// Offsets are relative to the data section; sorted ranges must cover every byte
// without holes or overlaps. Sub-byte dtypes must occupy an integral byte count.
func readSafetensors(r io.Reader, size int64) (map[string]uint64, int64, error) {
	var prefix [8]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, 0, err
	}
	n := binary.LittleEndian.Uint64(prefix[:])
	if size < 10 || n < 2 || n > maxJSONBytes || n > uint64(size-8) {
		return nil, 0, fmt.Errorf("invalid safetensors header length")
	}
	header := make([]byte, int(n))
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, 0, err
	}
	if header[0] != '{' {
		return nil, 0, fmt.Errorf("safetensors header must start with '{'")
	}
	tensors, err := parseHeader(header, uint64(size)-8-n)
	if err != nil {
		return nil, 0, err
	}
	read, err := io.Copy(io.Discard, r)
	if err != nil {
		return nil, 0, err
	}
	if read != size-8-int64(n) {
		return nil, 0, fmt.Errorf("safetensors data length changed")
	}
	return tensors, 8 + int64(n) + read, nil
}

type tensorRange struct {
	name       string
	start, end uint64
}

func parseHeader(header []byte, dataSize uint64) (map[string]uint64, error) {
	decoder, err := jsonDecoder(header)
	if err != nil {
		return nil, err
	}
	var ranges []tensorRange
	// One additional root member is reserved for __metadata__, not a tensor.
	tensors, err := jsonObject(decoder, maxTensors+1, func(name string) (uint64, error) {
		if name == "__metadata__" {
			_, err := jsonObject(decoder, maxMetadataValues, func(string) (struct{}, error) {
				_, err := jsonString(decoder)
				return struct{}{}, err
			})
			return 0, err
		}
		if len(ranges) == maxTensors {
			return 0, fmt.Errorf("shard exceeds %d tensors", maxTensors)
		}
		if name == "" {
			return 0, fmt.Errorf("empty tensor name")
		}
		span, err := parseTensor(decoder, name, dataSize)
		if err != nil {
			return 0, fmt.Errorf("tensor %q: %w", name, err)
		}
		ranges = append(ranges, span)
		return span.end - span.start, nil
	})
	if err != nil {
		return nil, err
	}
	if err := jsonEnd(decoder); err != nil {
		return nil, err
	}
	delete(tensors, "__metadata__")
	if len(tensors) == 0 {
		return nil, fmt.Errorf("shard must contain 1..%d tensors", maxTensors)
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end < ranges[j].end
		}
		return ranges[i].start < ranges[j].start
	})
	var end uint64
	for _, span := range ranges {
		if span.start != end {
			return nil, fmt.Errorf("tensor %q overlaps or leaves a hole", span.name)
		}
		end = span.end
	}
	if end != dataSize {
		return nil, fmt.Errorf("unindexed bytes in safetensors data section")
	}
	return tensors, nil
}

func parseTensor(decoder *json.Decoder, name string, dataSize uint64) (tensorRange, error) {
	var dtype string
	var shape, offsets []uint64
	fields, err := jsonObject(decoder, 3, func(key string) (struct{}, error) {
		var err error
		switch key {
		case "dtype":
			dtype, err = jsonString(decoder)
		case "shape":
			shape, err = unsignedArray(decoder, maxTensorRank)
		case "data_offsets":
			offsets, err = unsignedArray(decoder, 2)
		default:
			err = fmt.Errorf("unknown tensor field %q", key)
		}
		return struct{}{}, err
	})
	if err != nil {
		return tensorRange{}, err
	}
	if len(fields) != 3 {
		return tensorRange{}, fmt.Errorf("tensor requires dtype, shape and data_offsets")
	}
	bits := dtypeBits(dtype)
	if bits == 0 {
		return tensorRange{}, fmt.Errorf("unsupported tensor dtype %q", dtype)
	}
	elements := uint64(1)
	for _, dimension := range shape {
		if dimension != 0 && elements > math.MaxUint64/dimension {
			return tensorRange{}, fmt.Errorf("tensor shape overflow")
		}
		elements *= dimension
	}
	if elements > math.MaxUint64/bits {
		return tensorRange{}, fmt.Errorf("tensor bit size overflow")
	}
	bitSize := elements * bits
	if bitSize%8 != 0 {
		return tensorRange{}, fmt.Errorf("sub-byte tensor is not byte aligned")
	}
	if len(offsets) != 2 {
		return tensorRange{}, fmt.Errorf("data_offsets must have exactly two integers")
	}
	start, end := offsets[0], offsets[1]
	if end < start || end > dataSize || end-start != bitSize/8 {
		return tensorRange{}, fmt.Errorf("invalid offsets or shape size")
	}
	return tensorRange{name, start, end}, nil
}

func unsignedArray(decoder *json.Decoder, limit int) ([]uint64, error) {
	if err := jsonDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	result := make([]uint64, 0, min(limit, 4))
	for decoder.More() {
		if len(result) == limit {
			return nil, fmt.Errorf("integer array exceeds %d entries", limit)
		}
		value, err := jsonUnsigned(decoder)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := jsonDelimiter(decoder, ']'); err != nil {
		return nil, err
	}
	return result, nil
}

func jsonUnsigned(decoder *json.Decoder) (uint64, error) {
	token, err := decoder.Token()
	if err != nil {
		return 0, err
	}
	number, ok := token.(json.Number)
	if !ok {
		return 0, fmt.Errorf("expected unsigned integer")
	}
	value, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid unsigned integer: %w", err)
	}
	return value, nil
}

func dtypeBits(dtype string) uint64 {
	switch dtype {
	case "F4":
		return 4
	case "F6_E2M3", "F6_E3M2":
		return 6
	case "BOOL", "U8", "I8", "F8_E5M2", "F8_E4M3", "F8_E8M0", "F8_E4M3FNUZ", "F8_E5M2FNUZ":
		return 8
	case "I16", "U16", "F16", "BF16":
		return 16
	case "I32", "U32", "F32":
		return 32
	case "I64", "U64", "F64", "C64":
		return 64
	}
	return 0
}
