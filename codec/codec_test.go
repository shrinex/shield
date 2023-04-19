package codec

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type (
	UserDetails struct {
		AccountId int64  `json:"account_id"`
		Username  string `json:"username"`
		UserId    int64  `json:"user_id"`
		ShopId    int64  `json:"shop_id"`
		SysType   int64  `json:"sys_type"`
		IsAdmin   int64  `json:"is_admin"`
	}
)

var mockUser = UserDetails{
	AccountId: 1,
	Username:  "archer",
	UserId:    2,
	ShopId:    3,
	SysType:   4,
	IsAdmin:   5,
}

func TestCodec(t *testing.T) {
	codec := newCodec()

	json, err := codec.Encode(mockUser)
	assert.NoError(t, err)

	var user UserDetails
	err = codec.Decode(json, &user)
	assert.NoError(t, err)

	assert.Equal(t, mockUser, user)
}
