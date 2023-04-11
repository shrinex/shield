package security

import (
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/semgt"
)

type Builder[S semgt.Session] struct {
	authenticator authc.Authenticator
	authorizer    authz.Authorizer
	repository    semgt.Repository[S]
	registry      semgt.Registry[S]
}

func NewBuilder[S semgt.Session]() *Builder[S] {
	return &Builder[S]{}
}

func (b *Builder[S]) Authenticator(authenticator authc.Authenticator) *Builder[S] {
	b.authenticator = authenticator
	return b
}

func (b *Builder[S]) Authorizer(authorizer authz.Authorizer) *Builder[S] {
	b.authorizer = authorizer
	return b
}

func (b *Builder[S]) Repository(repository semgt.Repository[S]) *Builder[S] {
	b.repository = repository
	return b
}

func (b *Builder[S]) Registry(registry semgt.Registry[S]) *Builder[S] {
	b.registry = registry
	return b
}

func (b *Builder[S]) Build() Subject {
	return &subject[S]{
		authenticator: b.authenticator,
		authorizer:    b.authorizer,
		repository:    b.repository,
		registry:      b.registry,
	}
}
