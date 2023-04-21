package security

import (
	"context"
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/semgt"
	"sort"
)

type (
	// A Subject represents state and security operations for a single application user.
	// These operations include authentication (login/logout), authorization (access control),
	// and session access.
	// Subject can be created by Builder.
	Subject interface {
		// Authenticated returns true if this Subject/user proved their identity
		// during their current session by providing valid credentials matching
		// those known to the system, false otherwise
		Authenticated(context.Context) bool
		// Session returns the application Session associated with this Subject
		Session(context.Context) (semgt.Session, error)
		// UserDetails returns the authenticated user
		UserDetails(context.Context) (authc.UserDetails, error)

		// HasRole specifies a user requires an role
		HasRole(context.Context, authz.Role) bool
		// HasAnyRole specifies that a user requires one of many role
		HasAnyRole(context.Context, ...authz.Role) bool
		// HasAllRole specifies that a user requires all of roles
		HasAllRole(context.Context, ...authz.Role) bool

		// HasAuthority specifies a user requires an authority
		HasAuthority(context.Context, authz.Authority) bool
		// HasAnyAuthority specifies that a user requires one of many authorities
		HasAnyAuthority(context.Context, ...authz.Authority) bool
		// HasAllAuthority specifies that a user requires all of authorities
		HasAllAuthority(context.Context, ...authz.Authority) bool

		// Login performs a login attempt for this Subject
		Login(context.Context, authc.Token, ...LoginOption) (context.Context, error)
		// Logout logs out this Subject and invalidates and/or removes any
		// associated entities, such as a Session and authorization data
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

	s.logoutIfPossible(ctx, userDetails)

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
	err := s.applyGlobalOptions(ctx, userDetails, opt)
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

func (s *subject[S]) applyGlobalOptions(ctx context.Context, userDetails authc.UserDetails, opt *LoginOptions) error {
	sessions, err := s.registry.ActiveSessions(ctx, userDetails.Principal())
	if err != nil {
		return err
	}

	sessions, err = s.applyExclusiveOption(ctx, userDetails, sessions, opt)
	if err != nil {
		return err
	}

	err = s.applyConcurrencyOption(ctx, userDetails, sessions)
	if err != nil {
		return err
	}

	return nil
}

func (s *subject[S]) applyExclusiveOption(ctx context.Context, userDetails authc.UserDetails, sessions []S, opt *LoginOptions) ([]S, error) {
	if GetGlobalOptions().Exclusive {
		j := 0
		for _, ss := range sessions {
			platform, found, err := ss.AttributeAsString(ctx, PlatformKey)
			if err != nil {
				return nil, err
			}

			if !found || len(platform) == 0 {
				platform = DefaultPlatform
			}

			if opt.Platform != platform {
				sessions[j] = ss
				j += 1
				continue
			}

			// 同端互斥
			err = s.registry.Deregister(ctx, userDetails.Principal(), ss)
			if err != nil {
				return nil, err
			}

			err = s.repository.Remove(ctx, ss.Token())
			if err != nil {
				return nil, err
			}

			err = ss.SetAttribute(ctx, semgt.AlreadyReplacedKey, true)
			if err != nil {
				return nil, err
			}
		}

		return sessions[:j], nil
	}

	return sessions, nil
}

func (s *subject[S]) applyConcurrencyOption(ctx context.Context, userDetails authc.UserDetails, sessions []S) error {
	numSessions := len(sessions)
	concurrency := GetGlobalOptions().Concurrency
	if numSessions >= concurrency {
		sort.Sort(byLastAccessTime[S](sessions))
		expires := sessions[:numSessions-concurrency+1]
		for _, ss := range expires {
			err := s.registry.Deregister(ctx, userDetails.Principal(), ss)
			if err != nil {
				return err
			}

			err = s.repository.Remove(ctx, ss.Token())
			if err != nil {
				return err
			}

			err = ss.SetAttribute(ctx, semgt.AlreadyOverflowKey, true)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *subject[S]) createAndSaveSession(ctx context.Context, userDetails authc.UserDetails, opt *LoginOptions) (session S, err error) {
	// 创建新会话
	newToken := GetGlobalOptions().NewToken(userDetails)
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

func (s *subject[S]) logoutIfPossible(ctx context.Context, userDetails authc.UserDetails) {
	if la, ok := s.authenticator.(authc.LogoutAware); ok {
		la.Logout(ctx, userDetails)
	}

	if la, ok := s.authorizer.(authc.LogoutAware); ok {
		la.Logout(ctx, userDetails)
	}

	if la, ok := s.registry.(authc.LogoutAware); ok {
		la.Logout(ctx, userDetails)
	}

	if la, ok := s.repository.(authc.LogoutAware); ok {
		la.Logout(ctx, userDetails)
	}
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
