package security

import (
	"context"
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/semgt"
	"sort"
)

type (
	Subject interface {
		Authenticated(context.Context) bool
		Principal(ctx context.Context) (string, bool, error)
		Session(ctx context.Context) (semgt.Session, error)

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

	subject[S semgt.Session] struct {
		authenticator authc.Authenticator
		authorizer    authz.Authorizer
		repository    semgt.Repository[S]
		registry      semgt.Registry[S]
	}
)

var _ Subject = (*subject)(nil)

func (s *subject[S]) Authenticated(ctx context.Context) bool {
	session, err := s.Session(ctx)
	if err != nil {
		return false
	}

	return session != nil
}

func (s *subject[S]) Principal(ctx context.Context) (string, bool, error) {
	session, err := s.Session(ctx)
	if err != nil {
		return "", false, err
	}

	return session.AttributeAsString(ctx, PrincipalKey)
}

func (s *subject[S]) Session(ctx context.Context) (semgt.Session, error) {
	session, ok := ctx.Value(sessionCtxKey{}).(semgt.Session)
	if !ok {
		return nil, authc.ErrUnauthenticated
	}

	_, found, err := session.AttributeAsString(ctx, KickedOutKey)

	if err != nil {
		return nil, err
	}

	if found {
		return nil, ErrKickedOut
	}

	return session, nil
}

func (s *subject[S]) Login(ctx context.Context, token authc.Token, opts ...LoginOption) (context.Context, error) {
	// 先授权
	user, err := s.authenticator.Authenticate(ctx, token)
	if err != nil {
		return ctx, err
	}

	opt := apply(opts...)

	if opt.RenewToken {
		return s.loginWithNewToken(ctx, user, opt)
	}

	return s.loginWithOldToken(ctx, token)
}

func (s *subject[S]) Logout(ctx context.Context) (context.Context, error) {
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

	err = s.registry.Deregister(ctx, principal, session.(S))
	if err != nil {
		return nil, err
	}

	err = session.Stop(ctx)
	if err != nil {
		return nil, err
	}

	return context.WithValue(ctx, sessionCtxKey{}, nil), nil
}

func (s *subject[S]) HasRole(ctx context.Context, role authz.Role) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil || !found {
		return false, err
	}

	return s.authorizer.HasRole(ctx, principal, role), nil
}

func (s *subject[S]) HasAnyRole(ctx context.Context, roles ...authz.Role) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil || !found {
		return false, err
	}

	return s.authorizer.HasAnyRole(ctx, principal, roles...), nil
}

func (s *subject[S]) HasAllRole(ctx context.Context, roles ...authz.Role) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil || !found {
		return false, err
	}

	return s.authorizer.HasAllRole(ctx, principal, roles...), nil
}

func (s *subject[S]) HasAuthority(ctx context.Context, authority authz.Authority) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil || !found {
		return false, err
	}

	return s.authorizer.HasAuthority(ctx, principal, authority), nil
}

func (s *subject[S]) HasAnyAuthority(ctx context.Context, authorities ...authz.Authority) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil || !found {
		return false, err
	}

	return s.authorizer.HasAnyAuthority(ctx, principal, authorities...), nil
}

func (s *subject[S]) HasAllAuthority(ctx context.Context, authorities ...authz.Authority) (bool, error) {
	principal, found, err := s.Principal(ctx)
	if err != nil || !found {
		return false, err
	}

	return s.authorizer.HasAllAuthority(ctx, principal, authorities...), nil
}

//=====================================
//		    Private
//=====================================

func (s *subject[S]) loginWithNewToken(ctx context.Context, user authc.UserDetails, opt *LoginOptions) (context.Context, error) {
	session, err := s.createSession(ctx, user, opt)
	if err != nil {
		return nil, err
	}

	err = s.registerSession(ctx, user, session)
	if err != nil {
		return nil, err
	}

	return context.WithValue(ctx, sessionCtxKey{}, session), nil
}

func (s *subject[S]) createSession(ctx context.Context, user authc.UserDetails, opt *LoginOptions) (session S, err error) {
	// 创建新会话
	newToken := GetGlobalOptions().NewToken(user.Principal())
	session, err = s.repository.Create(ctx, newToken)
	if err != nil {
		return
	}

	// 存储用户信息
	err = session.SetAttribute(ctx, PlatformKey, opt.Platform)
	if err != nil {
		return
	}

	err = session.SetAttribute(ctx, PrincipalKey, user.Principal())
	if err != nil {
		return
	}

	err = session.SetAttribute(ctx, UserDetailsKey, user)
	if err != nil {
		return
	}

	// 保存会话
	err = s.repository.Save(ctx, session)
	if err != nil {
		return
	}

	return
}

func (s *subject[S]) registerSession(ctx context.Context, user authc.UserDetails, session S) error {
	// 踢掉多余的
	sessions, err := s.registry.ActiveSessions(ctx, user.Principal())
	if err != nil {
		return err
	}

	numSessions := len(sessions)
	concurrency := GetGlobalOptions().Concurrency
	if numSessions >= concurrency {
		sort.Sort(byLastAccessTime[S](sessions))
		expires := sessions[:numSessions-concurrency+1]
		for _, ss := range expires {
			err = ss.SetAttribute(ctx, KickedOutKey, true)
			if err != nil {
				return err
			}
		}
	}

	// 注册会话
	err = s.registry.Register(ctx, user.Principal(), session)
	if err != nil {
		return err
	}

	return nil
}

func (s *subject[S]) loginWithOldToken(ctx context.Context, token authc.Token) (context.Context, error) {
	session, found, err := s.repository.Read(ctx, token.Principal())
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, semgt.ErrAlreadyExpired
	}

	_ = session.Touch(ctx)

	return context.WithValue(ctx, sessionCtxKey{}, session), nil
}

func apply(opts ...LoginOption) *LoginOptions {
	opt := defaultLoginOptions

	for _, f := range opts {
		f(&opt)
	}

	return &opt
}

type byLastAccessTime[S semgt.Session] []S

func (s byLastAccessTime[S]) Len() int {
	return len(s)
}

func (s byLastAccessTime[S]) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byLastAccessTime[S]) Less(i, j int) bool {
	lhs, _ := s[i].LastAccessTime(context.TODO())
	rhs, _ := s[j].LastAccessTime(context.TODO())
	return lhs.Before(rhs)
}
