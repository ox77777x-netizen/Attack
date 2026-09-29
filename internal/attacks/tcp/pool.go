package tcp

import "sync"

// bufPool reuses byte buffers to reduce GC pressure under high throughput.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 512)
		return &b
	},
}
