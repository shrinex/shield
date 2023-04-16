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
		Session(context.Context) (semgt.Session, error)
		UserDetails(context.Context) (authc.UserDetails, error)

		HasRole(context.Context, authz.Role) bool
		HasAnyRole(context.Context, ...authz.Role) bool
		HasAllRole(context.Context, ...authz.Role) bool

		HasAuthority(context.Context, authz.Authority) bool
		HasAnyAuthority(context.Context, ...authz.Authority) bool
		HasAllAuthority(context.Context, ...authz.Authority) bool

		Login(context.Context, authc.Token, ...LoginOption) (context.Context, error)
		Logout(context.Context) (context.Context, error)
	}

	sessionCtxKey     struct{}
	userDetailsCtxKey struct{}

	subject[S semgt.Session] struct {
		authenticator authc.Authenticator
		authorizer    authz.Authorizer
		repository    semgt.Repository[S]
		registry      semgt.Registry[S]
	}
)

func (s *subject[S]) Authenticated(ctx context.Context) bool {
	session, err := s.Session(ctx)
	if err != nil {
		return false
	}

	return session != nil
}

func (s *subject[S]) UserDetails(ctx context.Context) (authc.UserDetails, error) {
	userDetails, ok := ctx.Value(userDetailsCtxKey{}).(authc.UserDetails)
	if !ok || userDetails == nil {
		return nil, authc.ErrUnauthenticated
	}

	return userDetails, nil
}

func (s *subject[S]) Session(ctx context.Context) (semgt.Session, error) {
	session, ok := ctx.Value(sessionCtxKey{}).(semgt.Session)
	if !ok || session == nil {
		return nil, authc.ErrUnauthenticated
	}

	return session, nil
}

func (s *subject[S]) Login(ctx context.Context, token authc.Token, opts ...LoginOption) (context.Context, error) {
	// 先授权
	userDetails, err := s.authenticator.Authenticate(ctx, token)
	if err != nil {
		return ctx, err
	}

	opt := apply(opts...)

	if opt.RenewToken {
		return s.loginWithNewToken(ctx, userDetails, opt)
	}

	return s.loginWithOldToken(ctx, token, userDetails)
}

func (s *subject[S]) Logout(ctx context.Context) (context.Context, error) {
	userDetails, err := s.UserDetails(ctx)
	if err != nil {
		return ctx, err
	}

	if la, ok := s.authenticator.(authc.LogoutAware); ok {
		la.Logout(ctx, userDetails)
	}

	session, err := s.Session(ctx)
	if err != nil {
		return ctx, err
	}

	err = s.registry.Deregister(ctx, userDetails.Principal(), session.(S))
	if err != nil {
		return ctx, err
	}

	err = s.repository.Remove(ctx, session.Token())
	if err != nil {
		return ctx, err
	}

	err = session.Stop(ctx)
	if err != nil {
		return ctx, err
	}
	ctx = context.WithValue(ctx, sessionCtxKey{}, nil)
	return context.WithValue(ctx, userDetailsCtxKey{}, nil), nil
}

func (s *subject[S]) HasRole(ctx context.Context, role authz.Role) bool {
	userDetails, err := s.UserDetails(ctx)
	if err != nil {
		return false
	}

	return s.authorizer.HasRole(ctx, userDetails, role)
}

func (s *subject[S]) HasAnyRole(ctx context.Context, roles ...authz.Role) bool {
	userDetails, err := s.UserDetails(ctx)
	if err != nil {
		return false
	}

	return s.authorizer.HasAnyRole(ctx, userDetails, roles...)
}

func (s *subject[S]) HasAllRole(ctx context.Context, roles ...authz.Role) bool {
	userDetails, err := s.UserDetails(ctx)
	if err != nil {
		return false
	}

	return s.authorizer.HasAllRole(ctx, userDetails, roles...)
}

func (s *subject[S]) HasAuthority(ctx context.Context, authority authz.Authority) bool {
	userDetails, err := s.UserDetails(ctx)
	if err != nil {
		return false
	}

	return s.authorizer.HasAuthority(ctx, userDetails, authority)
}

func (s *subject[S]) HasAnyAuthority(ctx context.Context, authorities ...authz.Authority) bool {
	userDetails, err := s.UserDetails(ctx)
	if err != nil {
		return false
	}

	return s.authorizer.HasAnyAuthority(ctx, userDetails, authorities...)
}

func (s *subject[S]) HasAllAuthority(ctx context.Context, authorities ...authz.Authority) bool {
	userDetails, err := s.UserDetails(ctx)
	if err != nil {
		return false
	}

	return s.authorizer.HasAllAuthority(ctx, userDetails, authorities...)
}

//=====================================
//		    Private
//=====================================

func (s *subject[S]) loginWithNewToken(ctx context.Context, userDetails authc.UserDetails, opt *LoginOptions) (context.Context, error) {
	err := s.kickOutOldestIfNeeded(ctx, userDetails)
	if err != nil {
		return ctx, err
	}

	session, err := s.createAndSaveSession(ctx, userDetails, opt)
	if err != nil {
		return ctx, err
	}

	err = s.registerSession(ctx, userDetails, session)
	if err != nil {
		return ctx, err
	}

	ctx = context.WithValue(ctx, sessionCtxKey{}, session)
	return context.WithValue(ctx, userDetailsCtxKey{}, userDetails), nil
}

func (s *subject[S]) kickOutOldestIfNeeded(ctx context.Context, userDetails authc.UserDetails) error {
	// 踢掉多余的
	sessions, err := s.registry.ActiveSessions(ctx, userDetails.Principal())
	if err != nil {
		return err
	}

	numSessions := len(sessions)
	concurrency := GetGlobalOptions().Concurrency
	if numSessions >= concurrency {
		sort.Sort(byLastAccessTime[S](sessions))
		expires := sessions[:numSessions-concurrency+1]
		for _, ss := range expires {
			err = s.registry.Deregister(ctx, userDetails.Principal(), ss)
			if err != nil {
				return err
			}

			err = s.repository.Remove(ctx, ss.Token())
			if err != nil {
				return err
			}

			err = ss.SetAttribute(ctx, semgt.AlreadyKickedOutKey, true)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *subject[S]) createAndSaveSession(ctx context.Context, userDetails authc.UserDetails, opt *LoginOptions) (session S, err error) {
	// 创建新会话
	newToken := GetGlobalOptions().NewToken(userDetails.Principal())
	session, err = s.repository.Create(ctx, newToken)
	if err != nil {
		return
	}

	// 存储用户信息
	err = session.SetAttribute(ctx, PlatformKey, opt.Platform)
	if err != nil {
		return
	}

	err = session.SetAttribute(ctx, UserDetailsKey, userDetails)
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

func (s *subject[S]) registerSession(ctx context.Context, userDetails authc.UserDetails, session S) error {
	// 注册会话
	err := s.registry.Register(ctx, userDetails.Principal(), session)
	if err != nil {
		return err
	}

	return nil
}

func (s *subject[S]) loginWithOldToken(ctx context.Context, token authc.Token, userDetails authc.UserDetails) (context.Context, error) {
	session, err := s.repository.Read(ctx, token.Principal())
	if err != nil {
		return ctx, err
	}

	_ = session.Touch(ctx)
	_ = s.registry.KeepAlive(ctx, userDetails.Principal())

	ctx = context.WithValue(ctx, sessionCtxKey{}, session)
	return context.WithValue(ctx, userDetailsCtxKey{}, userDetails), nil
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
