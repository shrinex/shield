package semgt

import (
	"container/list"
	"context"
	"sync"
	"time"
)

type (
	// Registry is used to maintain a registry of Session instances
	Registry[S Session] interface {
		// KeepAlive helps keep the Session alive, e.g. not expire
		KeepAlive(context.Context, string) error
		// Register registers Session under the specified principal
		Register(context.Context, string, S) error
		// Deregister deregister the specified Session
		Deregister(context.Context, string, S) error
		// ActiveSessions returns all active Session managed by this registry
		ActiveSessions(context.Context, string) ([]S, error)
	}

	signature struct {
		platform  string
		principal string
	}

	// MapSessionRegistry is a Registry backed by
	// a map and that uses a MapSessionRepository
	MapSessionRegistry struct {
		mu   sync.RWMutex
		repo *MapSessionRepository
		// lookup maps token to signature
		lookup map[string]signature
		// signs maps signature to tokens
		signs     map[signature]*list.List
		stopGuard sync.Once
		stopChan  chan struct{}
	}
)

var _ Registry[*MapSession] = (*MapSessionRegistry)(nil)

func NewRegistry(repo *MapSessionRepository) *MapSessionRegistry {
	r := &MapSessionRegistry{
		repo:   repo,
		lookup: make(map[string]signature),
		signs:  make(map[signature]*list.List),
	}

	go r.startCleanup()

	return r
}

func (r *MapSessionRegistry) Register(ctx context.Context, principal string, session *MapSession) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// already registered
	if _, ok := r.lookup[session.Token()]; ok {
		return nil
	}

	platform, found, err := session.AttributeAsString(ctx, "__platformKey")
	if err != nil {
		return err
	}

	if !found || len(platform) == 0 {
		platform = "universal"
	}

	// build relations
	sign := signature{
		platform:  platform,
		principal: principal,
	}
	if _, ok := r.signs[sign]; !ok {
		r.signs[sign] = list.New()
	}
	r.signs[sign].PushBack(session.Token())
	r.lookup[session.Token()] = sign

	return nil
}

func (r *MapSessionRegistry) Deregister(ctx context.Context, _ string, session *MapSession) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	sign, ok := r.lookup[session.Token()]
	if !ok {
		return nil
	}

	delete(r.lookup, session.Token())
	ls := r.signs[sign]
	for e := ls.Front(); e != nil; e = e.Next() {
		if e.Value.(string) == session.Token() {
			ls.Remove(e)
			break
		}
	}
	if ls.Len() == 0 {
		delete(r.signs, sign)
	}

	return nil
}

func (r *MapSessionRegistry) ActiveSessions(ctx context.Context, principal string) ([]*MapSession, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	r.mu.RLock()
	var ls *list.List
	for sign, l := range r.signs {
		if l != nil && sign.principal == principal {
			ls = l
			break
		}
	}
	r.mu.RUnlock()

	if ls == nil {
		return []*MapSession{}, nil
	}

	sessions := make([]*MapSession, 0)
	for e := ls.Front(); e != nil; e = e.Next() {
		session, err := r.repo.Read(ctx, e.Value.(string))
		if err != nil {
			return nil, err
		}

		if session != nil {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

func (r *MapSessionRegistry) KeepAlive(_ context.Context, _ string) error {
	return nil
}

func (r *MapSessionRegistry) StopCleanup() error {
	r.stopGuard.Do(func() {
		close(r.stopChan)
	})

	return nil
}

func (r *MapSessionRegistry) startCleanup() {
	ticker := time.NewTicker(3)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.deleteInactivated()
		case <-r.stopChan:
			break
		}
	}
}

func (r *MapSessionRegistry) deleteInactivated() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for sign, ls := range r.signs {
		if ls == nil {
			continue
		}

		ctx := context.Background()
		for e := ls.Front(); e != nil; e = e.Next() {
			session, err := r.repo.readSession(ctx, e.Value.(string), true)
			if err != nil {
				continue
			}

			if session != nil && session.GetExpired() {
				delete(r.lookup, session.Token())
				ls.Remove(e)
			}
		}

		if ls.Len() == 0 {
			delete(r.signs, sign)
		}
	}
}
