package semgt

import (
	"container/list"
	"context"
	"sync"
)

type (
	Registry[S Session] interface {
		Register(context.Context, string, S) error
		Deregister(context.Context, string, S) error
		ActiveSessions(context.Context, string) ([]S, error)
	}

	signature struct {
		platform  string
		principal string
	}

	MapSessionRegistry struct {
		mu   sync.RWMutex
		repo *MapSessionRepository
		// lookup maps token to signature
		lookup map[string]signature
		// signs maps signature to tokens
		signs map[signature]*list.List
	}
)

var _ Registry[*MapSession] = (*MapSessionRegistry)(nil)

func NewRegistry(repo *MapSessionRepository) *MapSessionRegistry {
	return &MapSessionRegistry{
		repo:   repo,
		lookup: make(map[string]signature),
		signs:  make(map[signature]*list.List),
	}
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

	return nil
}

func (r *MapSessionRegistry) ActiveSessions(ctx context.Context, principal string) ([]*MapSession, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	r.mu.RLock()
	lists := make([]*list.List, 0)
	for sign, ls := range r.signs {
		if ls == nil || sign.principal != principal {
			continue
		}
		lists = append(lists, ls)
	}
	r.mu.RUnlock()

	sessions := make([]*MapSession, 0)
	for _, ls := range lists {
		for e := ls.Front(); e != nil; e = e.Next() {
			session, err := r.repo.Read(ctx, e.Value.(string))
			if err != nil {
				return nil, err
			}

			if session != nil {
				sessions = append(sessions, session)
			}
		}
	}

	return sessions, nil
}
