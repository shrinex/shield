package security

import "encoding/json"

type (
	Encoder interface {
		Encode(v any) (string, error)
	}

	Decoder interface {
		Decode([]byte, any) error
	}

	encoder struct {
	}

	decoder struct {
	}
)

var _ Encoder = (*encoder)(nil)

func NewEncoder() Encoder {
	return &encoder{}
}

func (e *encoder) Encode(v any) (string, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

var _ Decoder = (*decoder)(nil)

func NewDecoder() Decoder {
	return &decoder{}
}

func (d *decoder) Decode(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
