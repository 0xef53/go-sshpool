package sshpool

import (
	"context"
	"io"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// PoolConfig defines configuration options of the pool.
type PoolConfig struct {
	// GCInterval specifies the frequency of Garbage Collector.
	GCInterval time.Duration

	// MaxConns is a maximum number of connections. GC will remove
	// the oldest connection from the pool if this limit is exceeded.
	MaxConns int
}

// Pool maintains a pool of SSH connections and sessions.
//
// The pool doesn't allow to derectly work with connections and sessions,
// but instead provides an interface to running commands with the appropriate
// credentials. This interface is similar to the standard functions
// of the ssh package: session.CombinedOutput(), session.Output() and session.Run().
//
// When executing commands the pool will reuse an existing connection if possible.
// If no connection exists, or if opening the session fails, a new connection
// will be created and added to the pool.
//
// Broken (non-established) and the oldest connections will be removed from the pool
// by the GC automatically according to the timeout specified in the pool configuration
// (default: 30s and no limit of max connections).
//
// The oldest connections will only be removed if the limit of max connections
// is reached.
//
// Keep in mind that after a call to Close, the pool can not be used again.
type SSHPool struct {
	PoolConfig

	ctx    context.Context
	cancel func()

	// Protects access to fields below
	mu    sync.Mutex
	table map[string]*SSHConn
}

// NewPool creates a new pool of connections and starts GC. If no configuration
// is specified (nil), defaults values are used.
func NewPool(cfg *PoolConfig) *SSHPool {
	ctx, cancel := context.WithCancel(context.Background())

	if cfg == nil {
		cfg = &PoolConfig{GCInterval: 30 * time.Second}
	}

	p := SSHPool{
		PoolConfig: *cfg,
		ctx:        ctx,
		cancel:     cancel,
		table:      make(map[string]*SSHConn),
	}

	if p.GCInterval > 0 {
		go p.collect()
	}

	return &p
}

// Collect removes broken and the oldest connections from the pool.
func (p *SSHPool) collect() {
	t := time.NewTicker(p.GCInterval)
	defer t.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-t.C:
		}

		needClose := func() []io.Closer {
			var out []io.Closer

			p.mu.Lock()
			defer p.mu.Unlock()

			// Releasing broken connections
			for hash, c := range p.table {
				if err := c.Err(); err != nil {
					delete(p.table, hash)
					out = append(out, c)
				}
			}

			if p.MaxConns == 0 || len(p.table) <= p.MaxConns {
				return out
			}

			// Releasing the oldest connections
			s := make([]*SSHConn, 0, len(p.table))
			for _, c := range p.table {
				s = append(s, c)
			}

			sort.SliceStable(s, func(i, j int) bool { return s[i].AccessTime().Unix() > s[j].AccessTime().Unix() })

			for _, c := range s[p.MaxConns:] {
				if c.RefCount() > 0 {
					continue
				}
				delete(p.table, c.Hash())
				out = append(out, c)
			}
			return out
		}()

		for _, c := range needClose {
			c.Close()
		}
	}
}

// NewSession creates and configures a new session reusing an existing
// SSH connection if possible.
//
// If no connection exists, or there are any problems with connection
// a new connection will be created and added to the pool. After this
// a new session will be set up.
func (p *SSHPool) newSession(cfg *SSHConfig, envs map[string]string) (*ssh.Session, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var err error
	conn, found := p.table[cfg.String()]
	if !found {
		conn, err = NewSSHConn(p.ctx, *cfg)
		if err != nil {
			return nil, nil, err
		}
		p.table[conn.Hash()] = conn
	}
	session, err := conn.NewSession(envs)
	if err != nil {
		return nil, nil, err
	}

	conn.IncrRefCount()

	return session, conn.DecrRefCount, nil
}

// Output runs command on the remote host and returns its standard output.
func (p *SSHPool) Output(cfg *SSHConfig, cmd string, in io.Reader, envs map[string]string) ([]byte, error) {
	session, closeFn, err := p.newSession(cfg, envs)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	defer closeFn()

	session.Stdin = in

	return session.Output(cmd)
}

// CombinedOutput runs command on the remote host and returns its combined
// standard output and standard error.
func (p *SSHPool) CombinedOutput(cfg *SSHConfig, cmd string, in io.Reader, envs map[string]string) ([]byte, error) {
	session, closeFn, err := p.newSession(cfg, envs)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	defer closeFn()

	session.Stdin = in

	return session.CombinedOutput(cmd)
}

// Run runs command on the remote host.
//
// See https://godoc.org/golang.org/x/crypto/ssh#Session.Run for details.
func (p *SSHPool) Run(cfg *SSHConfig, cmd string, in io.Reader, outWriter, errWriter io.Writer, envs map[string]string) error {
	session, closeFn, err := p.newSession(cfg, envs)
	if err != nil {
		return err
	}
	defer session.Close()
	defer closeFn()

	session.Stdout = outWriter
	session.Stderr = errWriter
	session.Stdin = in

	return session.Run(cmd)
}

// CloseConn closes and removes a connection corresponding to the given config
// from the pool.
func (p *SSHPool) CloseConn(cfg *SSHConfig) {
	hash := cfg.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	if c, found := p.table[hash]; found {
		c.Close()
		delete(p.table, hash)
	}
}

// Close closes the pool, thus destroying all connections.
// The pool cannot be used anymore after this call.
func (p *SSHPool) Close() {
	p.cancel()

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, c := range p.table {
		// It's ok, that we use here a blocking way
		// since pool cannot be used after it's closed.
		c.Close()
	}

	// Clearing the connection table.
	p.table = nil
}

// ActiveConns returns the number of connections handled by the pool thus far.
func (p *SSHPool) ActiveConns() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.table)
}
