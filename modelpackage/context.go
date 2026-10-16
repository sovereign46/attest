package modelpackage

import (
	"context"
	"io"
)

const readChunkBytes = 64 << 10

type scanHooks struct {
	afterRead func(name string, count int)
}

// Keep cancellation observable even when ReadFull requests a large header.
// Regular-file syscalls cannot be interrupted here; reads are bounded chunks.
type contextReader struct {
	ctx    context.Context
	source io.Reader
	name   string
	hooks  scanHooks
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > readChunkBytes {
		p = p[:readChunkBytes]
	}
	n, err := r.source.Read(p)
	if r.hooks.afterRead != nil {
		r.hooks.afterRead(r.name, n)
	}
	if canceled := r.ctx.Err(); canceled != nil {
		return n, canceled
	}
	return n, err
}
