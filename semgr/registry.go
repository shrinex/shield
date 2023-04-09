package semgr

import (
	"container/list"
	"context"
	"github.com/shrinex/shield/security"
	"sync"
)

type (
	Registry interface {
		Register(context.Context, Session) (string, error)
		Deregister(context.Context, Session) error
		KeepAlive(context.Context, Session) error
	}

	signature struct {
		hint      string
		principal string
	}

	registry struct {
		mu sync.RWMutex
		// lookup maps token to signature
		lookup map[string]signature
		// signs maps signature to tokens
		signs map[signature]*list.List
	}
)

var _ Registry = (*registry)(nil)

func NewRegistry() Registry {
	return &registry{
		lookup: make(map[string]signature),
		signs:  make(map[signature]*list.List),
	}
}

func (s *registry) Register(ctx context.Context, session Session) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	principal, found, err := session.Attribute(ctx, security.PrincipalKey)
	if err != nil {
		return "", err
	} else if !found {
		return "", nil
	}

	platform, found, err := session.Attribute(ctx, security.PlatformKey)
	if err != nil {
		return "", err
	} else if !found {
		platform = security.DefaultPlatform
	}

	// already registered
	if _, ok := s.lookup[session.Token()]; ok {
		return "", nil
	}

	// build relations
	sign := signature{
		hint:      platform,
		principal: principal,
	}
	if _, ok := s.signs[sign]; !ok {
		s.signs[sign] = list.New()
	}
	s.signs[sign].PushBack(session.Token())
	s.lookup[session.Token()] = sign

	// no enough room
	// kick the oldest out
	if s.signs[sign].Len() > security.GetGlobalOptions().Concurrency {
		value := s.signs[sign].Remove(s.signs[sign].Front())
		delete(s.lookup, value.(string))
		return value.(string), nil
	}

	return "", nil
}

func (s *registry) Deregister(ctx context.Context, session Session) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sign, ok := s.lookup[session.Token()]
	if !ok {
		return nil
	}

	delete(s.lookup, session.Token())
	l := s.signs[sign]
	for e := l.Front(); e != nil; e = e.Next() {
		if e.Value.(string) == session.Token() {
			l.Remove(e)
			break
		}
	}

	return nil
}

func (s *registry) KeepAlive(ctx context.Context, session Session) error {
	return nil
}
