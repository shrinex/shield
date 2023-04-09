package security

import (
	"github.com/google/uuid"
	"strings"
	"sync/atomic"
	"time"
)

type (
	Option func(*Options)

	Options struct {
		// Timeout 决定会话超时时间
		Timeout time.Duration
		// IdleTimeout 表示多久不进行操作就会过期
		IdleTimeout time.Duration
		// Concurrency 表示并发登录的数量
		Concurrency int
		// NewToken 指定 token 的生成函数
		NewToken func(any) string
	}

	LoginOption func(*LoginOptions)

	LoginOptions struct {
		// Platform 指定登录平台
		Platform string
		// RenewToken 指定登陆时是否需要生成 token
		RenewToken bool
		// Timeout 决定会话超时时间
		Timeout time.Duration
		// IdleTimeout 表示多久不进行操作就会过期
		IdleTimeout time.Duration
	}
)

//=====================================
//		   Global Options
//=====================================

func SetGlobalOptions(opts Options) {
	globalOptions.Store(&opts)
}

func GetGlobalOptions() *Options {
	return globalOptions.Load().(*Options)
}

var globalOptions = defaultGlobalOptions()

func defaultGlobalOptions() *atomic.Value {
	options := Options{
		Timeout:     12 * time.Hour,
		IdleTimeout: time.Hour,
		Concurrency: 1,
		NewToken: func(any) string {
			return strings.ReplaceAll(uuid.NewString(), "-", "")
		},
	}

	v := &atomic.Value{}
	v.Store(&options)
	return v
}

//=====================================
//		   Login Options
//=====================================

var defaultLoginOptions = LoginOptions{
	Platform:    DefaultPlatform,
	Timeout:     12 * time.Hour,
	IdleTimeout: time.Hour,
}

func WithPlatform(platform string) LoginOption {
	return func(opt *LoginOptions) {
		platform = strings.TrimSpace(platform)
		if len(platform) != 0 {
			opt.Platform = platform
		}
	}
}

func WithTimeout(timeout time.Duration) LoginOption {
	return func(opt *LoginOptions) {
		opt.Timeout = timeout
	}
}

func WithIdleTimeout(idleTimeout time.Duration) LoginOption {
	return func(opt *LoginOptions) {
		opt.IdleTimeout = idleTimeout
	}
}

func WithRenewToken(renewable bool) LoginOption {
	return func(opt *LoginOptions) {
		opt.RenewToken = renewable
	}
}
