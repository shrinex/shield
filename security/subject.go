package security

import (
	"context"
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/semgr"
	"time"
)

type (
	Subject interface {
		Authenticated(context.Context) bool
		Principal(ctx context.Context) (string, bool, error)
		Session(ctx context.Context) (semgr.Session, error)

		HasRole(context.Context, authz.Role) (bool, error)
		HasAnyRole(context.Context, ...authz.Role) (bool, error)
		HasAllRole(context.Context, ...authz.Role) (bool, error)

		HasAuthority(context.Context, authz.Authority) (bool, error)
		HasAnyAuthority(context.Context, ...authz.Authority) (bool, error)
		HasAllAuthority(context.Context, ...authz.Authority) (bool, error)

		Login(context.Context, authc.Token, ...LoginOption) (context.Context, error)
		Logout(context.Context) (context.Context, error)
	}

	sessionCtxKey struct{}

	subject struct {
		authenticator authc.Authenticator
		authorizer    authz.Authorizer
		repository    semgr.Repository
		registry      semgr.Registry
		encoder       Encoder
	}
)

var _ Subject = (*subject)(nil)

func (s *subject) Authenticated(ctx context.Context) bool {
	session, ok := ctx.Value(sessionCtxKey{}).(semgr.Session)
	if !ok {
		return false
	}

	_, found, err := session.Attribute(ctx, KickedOutKey)
	if err != nil || found {
		return false
	}

	return true
}

func (s *subject) Principal(ctx context.Context) (string, bool, error) {
	session, err := s.Session(ctx)
	if err != nil {
		return "", false, err
	}

	principal, ok, err := session.Attribute(ctx, PrincipalKey)
	if err != nil || !ok {
		return "", false, err
	}

	return principal, true, nil
}

func (s *subject) Session(ctx context.Context) (semgr.Session, error) {
	session, ok := ctx.Value(sessionCtxKey{}).(semgr.Session)
	if !ok {
		panic("no session available")
	}

	_, found, err := session.Attribute(ctx, KickedOutKey)
	if err != nil {
		return nil, err
	} else if found {
		return nil, ErrKickedOut
	}

	return session, nil
}

func (s *subject) Login(ctx context.Context, token authc.Token, opts ...LoginOption) (context.Context, error) {
	// 先授权
	user, err := s.authenticator.Authenticate(ctx, token)
	if err != nil {
		return ctx, err
	}

	opt := apply(opts...)

	if opt.RenewToken {
		return s.loginWithNewToken(ctx, user, &opt)
	}

	return s.loginWithOldToken(ctx, user)
}

func (s *subject) Logout(ctx context.Context) (context.Context, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil {
		return ctx, err
	} else if !found {
		return ctx, nil
	}

	if la, ok := s.authenticator.(authc.LogoutAware); ok {
		la.Logout(ctx, principal)
	}

	session, err := s.Session(ctx)
	if err != nil {
		return nil, err
	}

	err = s.repository.Remove(ctx, session.Token())
	if err != nil {
		return nil, err
	}

	err = s.registry.Deregister(ctx, session)
	if err != nil {
		return nil, err
	}

	err = session.Stop(ctx)
	if err != nil {
		return nil, err
	}

	return context.WithValue(ctx, sessionCtxKey{}, nil), nil
}

func (s *subject) HasRole(ctx context.Context, role authz.Role) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil {
		return false, err
	} else if !found {
		return false, nil
	}

	return s.authorizer.HasRole(ctx, principal, role), nil
}

func (s *subject) HasAnyRole(ctx context.Context, roles ...authz.Role) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil {
		return false, err
	} else if !found {
		return false, nil
	}

	return s.authorizer.HasAnyRole(ctx, principal, roles...), nil
}

func (s *subject) HasAllRole(ctx context.Context, roles ...authz.Role) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil {
		return false, err
	} else if !found {
		return false, nil
	}

	return s.authorizer.HasAllRole(ctx, principal, roles...), nil
}

func (s *subject) HasAuthority(ctx context.Context, authority authz.Authority) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil {
		return false, err
	} else if !found {
		return false, nil
	}
	return s.authorizer.HasAuthority(ctx, principal, authority), nil
}

func (s *subject) HasAnyAuthority(ctx context.Context, authorities ...authz.Authority) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil {
		return false, err
	} else if !found {
		return false, nil
	}
	return s.authorizer.HasAnyAuthority(ctx, principal, authorities...), nil
}

func (s *subject) HasAllAuthority(ctx context.Context, authorities ...authz.Authority) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil {
		return false, err
	} else if !found {
		return false, nil
	}

	return s.authorizer.HasAllAuthority(ctx, principal, authorities...), nil
}

//=====================================
//		    Private
//=====================================

func (s *subject) loginWithNewToken(ctx context.Context, user authc.UserDetails, opt *LoginOptions) (context.Context, error) {
	session, err := s.createSession(ctx, user, opt)
	if err != nil {
		return nil, err
	}

	err = s.registerSession(ctx, session)
	if err != nil {
		return nil, err
	}

	return context.WithValue(ctx, sessionCtxKey{}, session), nil
}

func (s *subject) createSession(ctx context.Context, user authc.UserDetails, opt *LoginOptions) (semgr.Session, error) {
	// 创建新会话
	newToken := GetGlobalOptions().NewToken(user.Principal())
	session, err := s.repository.Create(ctx, newToken, timeout(opt), idleTimeout(opt))
	if err != nil {
		return nil, err
	}

	// 存储用户信息
	err = session.SetAttribute(ctx, PlatformKey, opt.Platform)
	if err != nil {
		return nil, err
	}

	err = session.SetAttribute(ctx, PrincipalKey, user.Principal())
	if err != nil {
		return nil, err
	}

	encoded, err := s.encoder.Encode(user)
	if err != nil {
		return nil, err
	}

	err = session.SetAttribute(ctx, UserDetailsKey, encoded)
	if err != nil {
		return nil, err
	}

	// 保存会话
	err = s.repository.Save(ctx, session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *subject) registerSession(ctx context.Context, session semgr.Session) error {
	// 注册会话
	token2KickOut, err := s.registry.Register(ctx, session)
	if err != nil {
		return err
	}

	return s.kickOutOldest(ctx, token2KickOut)
}

func (s *subject) kickOutOldest(ctx context.Context, token2KickOut string) error {
	if len(token2KickOut) == 0 {
		return nil
	}

	session2KickOut, found, err := s.repository.Read(ctx, token2KickOut)
	if err != nil {
		return err
	} else if found {
		err = session2KickOut.SetAttribute(ctx, KickedOutKey, "true")
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *subject) loginWithOldToken(ctx context.Context, user authc.UserDetails) (context.Context, error) {
	session, found, err := s.repository.Read(ctx, user.Principal())
	if err != nil {
		return nil, err
	} else if !found {
		return nil, semgr.ErrAlreadyExpired
	}

	_ = session.Touch(ctx)
	_ = s.registry.KeepAlive(ctx, session)

	return context.WithValue(ctx, sessionCtxKey{}, session), nil
}

func apply(opts ...LoginOption) LoginOptions {
	opt := defaultLoginOptions

	for _, f := range opts {
		f(&opt)
	}

	return opt
}

func timeout(opt *LoginOptions) time.Duration {
	if opt.Timeout > 0 {
		return opt.Timeout
	}

	if GetGlobalOptions().Timeout > 0 {
		return GetGlobalOptions().Timeout
	}

	return time.Hour
}

func idleTimeout(opt *LoginOptions) time.Duration {
	if opt.IdleTimeout > 0 {
		return opt.IdleTimeout
	}

	if GetGlobalOptions().IdleTimeout > 0 {
		return GetGlobalOptions().IdleTimeout
	}

	return timeout(opt)
}
