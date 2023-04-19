package security

import (
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/semgt"
)

// Builder provides a way to create Subject
type Builder[S semgt.Session] struct {
	authenticator authc.Authenticator
	authorizer    authz.Authorizer
	repository    semgt.Repository[S]
	registry      semgt.Registry[S]
}

// NewBuilder returns a newly created Builder
func NewBuilder[S semgt.Session]() *Builder[S] {
	return &Builder[S]{}
}

// Authenticator supplies an authenticator used by Subject
func (b *Builder[S]) Authenticator(authenticator authc.Authenticator) *Builder[S] {
	b.authenticator = authenticator
	return b
}

// Authorizer supplies an authorizer used by Subject
func (b *Builder[S]) Authorizer(authorizer authz.Authorizer) *Builder[S] {
	b.authorizer = authorizer
	return b
}

// Repository supplies a repository to help Subject create/read/update/remove a semgt.Session
func (b *Builder[S]) Repository(repository semgt.Repository[S]) *Builder[S] {
	b.repository = repository
	return b
}

// Registry supplies a registry to help Subject manages semgt.Session(s)
func (b *Builder[S]) Registry(registry semgt.Registry[S]) *Builder[S] {
	b.registry = registry
	return b
}

// Build creates the Subject
func (b *Builder[S]) Build() Subject {
	if b.authenticator == nil || b.authorizer == nil ||
		b.repository == nil || b.registry == nil {
		panic("nil")
	}
	return &subject[S]{
		authenticator: b.authenticator,
		authorizer:    b.authorizer,
		repository:    b.repository,
		registry:      b.registry,
	}
}
