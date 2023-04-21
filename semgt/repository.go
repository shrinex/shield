package semgt

import (
	"context"
	"github.com/shrinex/shield/codec"
	"sync"
	"time"
)

type (
	// Repository is an interface for manipulating Session instances
	Repository[S Session] interface {
		// Save ensures the Session created by Create is saved
		Save(context.Context, S) error
		// Remove the Session with the given token or does nothing if the Session is not found
		Remove(context.Context, string) error
		// Read the Session by the token or nil if no Session is found
		// Note that Read never returns an expired Session
		Read(context.Context, string) (S, error)
		// Create a new Session that is capable of being persisted by this Repository
		Create(context.Context, string) (S, error)
	}

	// MapSessionRepository is a Repository backed by a map and that uses a MapSession
	MapSessionRepository struct {
		mu          sync.RWMutex
		stopGuard   sync.Once
		codec       codec.Codec
		stopChan    chan struct{}
		timeout     time.Duration
		idleTimeout time.Duration
		lookup      map[string]*MapSession
	}
)

var _ Repository[*MapSession] = (*MapSessionRepository)(nil)

func NewRepository(codec codec.Codec, timeout time.Duration,
	idleTimeout time.Duration) *MapSessionRepository {
	r := &MapSessionRepository{
		codec:       codec,
		timeout:     timeout,
		idleTimeout: idleTimeout,
		stopChan:    make(chan struct{}),
		lookup:      make(map[string]*MapSession),
	}

	go r.startCleanup()

	return r
}

func (r *MapSessionRepository) Create(ctx context.Context, token string) (*MapSession, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	session := NewSessionTimeout(
		token,
		r.codec,
		r.timeout,
		r.idleTimeout,
	)
	r.lookup[token] = session

	return session, nil
}

func (r *MapSessionRepository) Read(ctx context.Context, token string) (*MapSession, error) {
	return r.readSession(ctx, token, false)
}

func (r *MapSessionRepository) Save(ctx context.Context, session *MapSession) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.lookup[session.Token()] = session

	return nil
}

func (r *MapSessionRepository) Remove(ctx context.Context, token string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.lookup[token]; ok {
		delete(r.lookup, token)
		return nil
	}

	return nil
}

func (r *MapSessionRepository) readSession(ctx context.Context, token string, allowExpired bool) (*MapSession, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	r.mu.RLock()
	session, ok := r.lookup[token]
	r.mu.RUnlock()

	if !ok {
		return nil, nil
	}

	if !allowExpired && session.GetExpired() {
		_ = r.Remove(ctx, token)
		_ = session.Stop(ctx)
		return nil, nil
	}

	return session, nil
}

func (r *MapSessionRepository) StopCleanup() error {
	r.stopGuard.Do(func() {
		close(r.stopChan)
	})

	return nil
}

func (r *MapSessionRepository) startCleanup() {
	ticker := time.NewTicker(5)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.deleteExpired()
		case <-r.stopChan:
			break
		}
	}
}

func (r *MapSessionRepository) deleteExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()

	ctx := context.TODO()
	for _, ss := range r.lookup {
		if expired := ss.GetExpired(); expired {
			delete(r.lookup, ss.Token())
			_ = ss.Stop(ctx)
		}
	}
}
