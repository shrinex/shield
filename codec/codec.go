package codec

import "encoding/json"

type (
	// Encoder is used to serialize the specified attribute value
	Encoder interface {
		Encode(v any) (string, error)
	}

	// Decoder is used to deserialize the specified attribute value
	Decoder interface {
		Decode(string, any) error
	}

	// Codec combines Encoder & Decoder
	Codec interface {
		Encoder
		Decoder
	}

	codec struct {
	}
)

var (
	// JSON codec
	JSON = newCodec()

	_ Codec = (*codec)(nil)
)

func newCodec() Codec {
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
