package codec

import "encoding/json"

type (
	Encoder interface {
		Encode(v any) (string, error)
	}

	Decoder interface {
		Decode(string, any) error
	}

	Codec interface {
		Encoder
		Decoder
	}

	codec struct {
	}
)

var _ Codec = (*codec)(nil)

func NewCodec() Codec {
	return &codec{}
}

func (c *codec) Encode(v any) (string, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (c *codec) Decode(data string, v any) error {
	return json.Unmarshal([]byte(data), v)
}
