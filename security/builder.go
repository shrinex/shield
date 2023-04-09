package security

import (
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/semgr"
)

type Builder struct {
	authenticator authc.Authenticator
	authorizer    authz.Authorizer
	repository    semgr.Repository
	registry      semgr.Registry
	encoder       Encoder
}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) Authenticator(authenticator authc.Authenticator) *Builder {
	b.authenticator = authenticator
	return b
}

func (b *Builder) Authorizer(authorizer authz.Authorizer) *Builder {
	b.authorizer = authorizer
	return b
}

func (b *Builder) Repository(repository semgr.Repository) *Builder {
	b.repository = repository
	return b
}

func (b *Builder) Registry(registry semgr.Registry) *Builder {
	b.registry = registry
	return b
}

func (b *Builder) Encoder(encoder Encoder) *Builder {
	b.encoder = encoder
	return b
}

func (b *Builder) Build() Subject {
	return &subject{
		authenticator: b.authenticator,
		authorizer:    b.authorizer,
		repository:    b.repository,
		registry:      b.registry,
		encoder:       b.encoder,
	}
}
