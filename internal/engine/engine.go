package engine

import (
	"context"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	targetpkg "github.com/sammwyy/mikumikubeam/pkg/target"
)

// AttackKind enumerates supported attack types.
type AttackKind string

const (
	AttackHTTPFlood     AttackKind = "http_flood"
	AttackHTTPBurst     AttackKind = "http_burst"
	AttackHTTPBypass    AttackKind = "http_bypass"
	AttackHTTPSlowloris AttackKind = "http_slowloris"
	AttackTCPFlood      AttackKind = "tcp_flood"
	AttackTCPBurst      AttackKind = "tcp_burst"
	AttackTCPSlowloris  AttackKind = "tcp_slowloris"
	AttackMinecraftPing AttackKind = "minecraft_ping"
)

// AttackParams are common parameters for an attack.
type AttackParams struct {
	Target      string
	TargetNode  targetpkg.Node
	Duration    time.Duration
	PacketDelay time.Duration
	PacketSize  int
	Method      AttackKind
	Threads     int
	Verbose     bool // Whether to send detailed logs
}

// Proxy represents a network proxy.
type Proxy struct {
	Username string
	Password string
	Protocol string
	Host     string
	Port     int
}

// AttackStats represents live stats reported by workers.
type AttackStats struct {
	Timestamp    time.Time
	PacketsPerS  int64
	TotalPackets int64
	Proxies      int
	Log          string
}

// AttackWorker is implemented by each attack method implementation.
type AttackWorker interface {
	// Fire sends a single payload for the given params using the provided proxy and user agent.
	// It should return quickly and not block the caller; engine will dispatch concurrently.
	// The log channel can be used to send individual attack logs.
	Fire(ctx context.Context, params AttackParams, proxy Proxy, userAgent string, logCh chan<- AttackStats) error
}

// Engine coordinates attacks and worker lifecycles.
type Engine struct {
	registry Registry
	mu       sync.RWMutex
	attacks  map[string]*AttackInstance // attackID -> AttackInstance
}

// AttackInstance represents a single running attack
type AttackInstance struct {
	ID        string
	Params    AttackParams
	Cancel    context.CancelFunc
	StatsCh   chan AttackStats
	TotalSent int64 // accessed atomically — do NOT use mutex
}

func NewEngine(reg Registry) *Engine {
	return &Engine{
		registry: reg,
		attacks:  make(map[string]*AttackInstance),
	}
}

// Start launches a new attack with a unique ID
func (e *Engine) Start(attackID string, parent context.Context, params AttackParams, proxies []Proxy, userAgents []string) (<-chan AttackStats, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Stop existing attack with same ID if running
	if existing, exists := e.attacks[attackID]; exists {
		existing.Cancel()
		delete(e.attacks, attackID)
	}

	worker, ok := e.registry.Get(params.Method)
	if !ok {
		// Create a temporary stats channel for unsupported method
		tempCh := make(chan AttackStats, 1)
		tempCh <- AttackStats{Timestamp: time.Now(), Log: "unsupported attack method"}
		close(tempCh)
		return tempCh, nil
	}

	// Use context.WithTimeout for attack duration instead of manual deadline checks.
	// This ensures ALL goroutines (including pending Fire() calls) get cancelled on expiry.
	var ctx context.Context
	var cancel context.CancelFunc
	if params.Duration > 0 {
		ctx, cancel = context.WithTimeout(parent, params.Duration)
	} else {
		ctx, cancel = context.WithCancel(parent)
	}

	statsCh := make(chan AttackStats, 1024)

	instance := &AttackInstance{
		ID:      attackID,
		Params:  params,
		Cancel:  cancel,
		StatsCh: statsCh,
	}

	e.attacks[attackID] = instance

	// Determine threads
	threads := params.Threads
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	proxyCount := len(proxies)
	uaCount := len(userAgents)

	// Semaphore to limit concurrent Fire goroutines — prevents unbounded goroutine growth
	maxConcurrent := threads * 64
	if maxConcurrent < 256 {
		maxConcurrent = 256
	}
	sem := make(chan struct{}, maxConcurrent)

	// Aggregator: send stats every second
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var lastTotal int64
		for {
			select {
			case <-ctx.Done():
				// Drain remaining messages to prevent goroutine leaks in writers
				for {
					select {
					case <-statsCh:
					default:
						close(statsCh)
						e.mu.Lock()
						delete(e.attacks, attackID)
						e.mu.Unlock()
						return
					}
				}
			case t := <-ticker.C:
				total := atomic.LoadInt64(&instance.TotalSent)
				delta := total - lastTotal
				lastTotal = total
				// Only send stats if there's actual activity (delta > 0) or it's the first tick
				if delta > 0 || lastTotal == 0 {
					select {
					case statsCh <- AttackStats{
						Timestamp:    t,
						PacketsPerS:  delta,
						TotalPackets: total,
						Proxies:      proxyCount,
						Log:          "", // Empty log - individual workers will send their own logs
					}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// Thread loops
	for i := 0; i < threads; i++ {
		go func(threadID int) {
			ticker := time.NewTicker(params.PacketDelay)
			defer ticker.Stop()

			dispatch := func() {
				// pick proxy and ua (random)
				var p Proxy
				var ua string
				if proxyCount > 0 {
					p = proxies[rand.Intn(proxyCount)]
				}
				if uaCount > 0 {
					ua = userAgents[rand.Intn(uaCount)]
				}

				// Acquire semaphore (respects context cancellation to avoid blocking on shutdown)
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}

				go func() {
					defer func() { <-sem }()
					// Only count after Fire succeeds — gives accurate stats
					if err := worker.Fire(ctx, params, p, ua, statsCh); err == nil {
						atomic.AddInt64(&instance.TotalSent, 1)
					}
				}()
			}

			// immediate first dispatch
			dispatch()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					dispatch()
				}
			}
		}(i)
	}

	return statsCh, nil
}

// Stop cancels a specific attack by ID
func (e *Engine) Stop(attackID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if instance, exists := e.attacks[attackID]; exists {
		// Cancel the context first to stop all workers
		instance.Cancel()
		// Remove from map immediately to prevent new operations
		delete(e.attacks, attackID)
	}
}

// StopAll cancels all running attacks
func (e *Engine) StopAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, instance := range e.attacks {
		instance.Cancel()
	}
	e.attacks = make(map[string]*AttackInstance)
}

// IsRunning checks if a specific attack is running
func (e *Engine) IsRunning(attackID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, exists := e.attacks[attackID]
	return exists
}

// GetRunningAttacks returns a list of running attack IDs
func (e *Engine) GetRunningAttacks() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, 0, len(e.attacks))
	for id := range e.attacks {
		ids = append(ids, id)
	}
	return ids
}
