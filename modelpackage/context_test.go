package modelpackage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContextAPIs(t *testing.T) {
	root := fixture(t)
	manifest, err := BuildContext(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyContext(context.Background(), root, manifest); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, ctx := range []context.Context{canceled, expired} {
		got, err := BuildContext(ctx, root)
		if !errors.Is(err, ctx.Err()) || len(got.Files) != 0 {
			t.Fatalf("canceled build returned manifest or wrong error: %+v, %v", got, err)
		}
		if err := VerifyContext(ctx, root, manifest); !errors.Is(err, ctx.Err()) {
			t.Fatalf("canceled verify: %v", err)
		}
	}
}

func TestCheckpointCancellationDuringShardRead(t *testing.T) {
	root := fixture(t)
	const shardName = "model-00001-of-00002.safetensors"
	const payloadBytes = 2 << 20
	// The header itself is larger than a read chunk: ReadFull must not bypass
	// cancellation just because the file is being structurally parsed.
	header := fmt.Sprintf(`{"__metadata__":{"description":%q},"weight":{"dtype":"U8","shape":[%d],"data_offsets":[0,%d]}}`, strings.Repeat("x", 128<<10), payloadBytes, payloadBytes)
	shard := safetensors(header, make([]byte, payloadBytes))
	write(t, filepath.Join(root, shardName), shard)
	write(t, filepath.Join(root, "model.safetensors.index.json"), []byte(fmt.Sprintf(`{"metadata":{"total_size":%d},"weight_map":{"weight":"%s","scale":"model-00002-of-00002.safetensors","quant":"model-00002-of-00002.safetensors"}}`, payloadBytes+4, shardName)))
	manifest, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, threshold := range map[string]int{
		"prefix":     1,
		"header":     8 + readChunkBytes,
		"payload":    len(shard) - payloadBytes + readChunkBytes,
		"last chunk": len(shard),
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			read := 0
			hooks := scanHooks{afterRead: func(path string, n int) {
				if ctx.Err() != nil {
					t.Fatal("checkpoint read continued after cancellation")
				}
				if n > readChunkBytes {
					t.Fatalf("unbounded read: %d", n)
				}
				if path == shardName {
					read += n
					if read >= threshold {
						cancel()
					}
				}
			}}
			// This is the same scan invoked by VerifyContext after canonicalizing
			// its manifest; the hook cancels synchronously after actual file I/O.
			got, err := build(ctx, root, manifest.Files, hooks)
			if !errors.Is(err, context.Canceled) || len(got.Files) != 0 {
				t.Fatalf("canceled shard returned manifest or wrong error: %+v, %v", got, err)
			}
			if read < threshold || read > threshold+readChunkBytes {
				t.Fatalf("unexpected cancellation boundary: read=%d threshold=%d", read, threshold)
			}
		})
	}
	if err := VerifyContext(context.Background(), root, manifest); err != nil {
		t.Fatalf("cancellation changed the checkpoint: %v", err)
	}
}
