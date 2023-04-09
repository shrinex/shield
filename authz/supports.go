package authz

type (
	role string

	authority string
)

var _ Role = (*role)(nil)

func NewRole(name string) Role {
	return role(name)
}

func (r role) RawValue() string {
	return string(r)
}

func (r role) Implies(role Role) bool {
	return r.RawValue() == role.RawValue()
}

var _ Authority = (*authority)(nil)

func NewAuthority(name string) Authority {
	return authority(name)
}

func (a authority) RawValue() string {
	return string(a)
}

func (a authority) Implies(authority Authority) bool {
	return a.RawValue() == authority.RawValue()
}
