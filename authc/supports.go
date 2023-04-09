package authc

type (
	BearerToken struct {
		value string
	}

	UsernamePasswordToken struct {
		username string
		password string
	}
)

var _ Token = (*BearerToken)(nil)

func NewBearerToken(value string) Token {
	return &BearerToken{value: value}
}

func (bt *BearerToken) Principal() string {
	return bt.value
}

func (bt *BearerToken) Credentials() string {
	return bt.value
}

var _ Token = (*UsernamePasswordToken)(nil)

func NewUsernamePasswordToken(username string, password string) Token {
	return &UsernamePasswordToken{username: username, password: password}
}

func (upt *UsernamePasswordToken) Principal() string {
	return upt.username
}

func (upt *UsernamePasswordToken) Credentials() string {
	return upt.password
}
