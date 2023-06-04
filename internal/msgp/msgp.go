// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package msgp

import (
	"io"

	"github.com/tinylib/msgp/msgp"
)

type Marshaler[T any] interface {
	MarshalMsg() (T, error)
}

type Unmarshaler[T any] interface {
	UnmarshalMsg(T) error
}

func Marshal[M any, C interface {
	msgp.MarshalSizer
	*M
}, T Marshaler[M]](v T,
) ([]byte, error) {
	m, err := v.MarshalMsg()
	if err != nil {
		return nil, err
	}
	var c C = &m
	out := make([]byte, 0, c.Msgsize())
	return c.MarshalMsg(out)
}

func Unmarshal[M any, C interface {
	msgp.Unmarshaler
	*M
}, T Unmarshaler[C]](b []byte, v T,
) error {
	var m M
	var c C = &m
	if _, err := c.UnmarshalMsg(b); err != nil {
		return err
	}
	return v.UnmarshalMsg(c)
}

func Encode[M interface {
	msgp.MarshalSizer
	msgp.Encodable
}, T Marshaler[M]](w io.Writer, v T,
) error {
	m, err := v.MarshalMsg()
	if err != nil {
		return err
	}
	return msgp.Encode(w, m)
}

func Decode[M any, U interface {
	msgp.Unmarshaler
	msgp.Decodable
	*M
}, T Unmarshaler[U]](r io.Reader, v T,
) error {
	var m M
	var u U = &m
	if err := msgp.Decode(r, u); err != nil {
		return err
	}
	return v.UnmarshalMsg(u)
}
