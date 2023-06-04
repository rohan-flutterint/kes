// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package uint128

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"strconv"

	"github.com/minio/kes/internal/msgp"
)

type Uint128 struct {
	high, low uint64
}

// Inc returns a new Counter n = c + 1.
// If c + 1 overflows it returns 0.
func (c Uint128) Inc() Uint128 {
	low, carry := bits.Add64(c.low, 1, 0)
	return Uint128{
		low:  low,
		high: c.high + carry,
	}
}

// IsZero reports whether c == 0.
func (c Uint128) IsZero() bool { return c.low == 0 && c.high == 0 }

// Less reports whether c < o.
func (c Uint128) Less(o Uint128) bool {
	return c.high < o.high || (c.high == o.high && c.low < o.low)
}

// LessOrEqual reports whether c <= o.
func (c Uint128) LessOrEqual(o Uint128) bool { return !c.Greater(o) }

// Greater reports whether c > o.
func (c Uint128) Greater(o Uint128) bool {
	return c.high > o.high || (c.high == o.high && c.low > o.low)
}

// GreaterOrEqual reports whether c >= o.
func (c Uint128) GreaterOrEqual(o Uint128) bool { return !c.Less(o) }

func (c Uint128) MarshalJSON() ([]byte, error) {
	var buf [1 + 20 + 1 + 20 + 1]byte
	out := append(buf[:0], '[')
	out = strconv.AppendUint(out, c.low, 10)
	out = append(out, ',')
	out = strconv.AppendUint(out, c.high, 10)
	return append(out, ']'), nil
}

func (c *Uint128) UnmarshalJSON(text []byte) error {
	text = bytes.TrimSpace(text)
	if len(text) <= 3 || text[0] != '[' || text[len(text)-1] != ']' {
		return errors.New("raft: invalid counter: invalid JSON array")
	}

	text = text[1 : len(text)-1]
	i := bytes.IndexRune(text, ',')
	if i < 0 {
		return errors.New("raft: invalid counter: no high value")
	}
	low, high := text[:i], text[1:]

	l, err := strconv.ParseUint(string(low), 10, 64)
	if err != nil {
		return err
	}
	h, err := strconv.ParseUint(string(high), 10, 64)
	if err != nil {
		return err
	}

	c.low, c.high = l, h
	return nil
}

func (c Uint128) MarshalMsg() (msgp.Uint128, error) {
	return msgp.Uint128{Low: c.low, High: c.high}, nil
}

func (c *Uint128) UnmarshalMsg(v *msgp.Uint128) error {
	c.low, c.high = v.Low, v.High
	return nil
}

func (c Uint128) MarshalBinary() ([]byte, error) {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:8], c.low)
	binary.LittleEndian.PutUint64(b[8:], c.high)
	return b[:], nil
}

func (c *Uint128) UnmarshalBinary(b []byte) error {
	if len(b) != 16 {
		return errors.New("consens: invalid counter")
	}
	c.low = binary.LittleEndian.Uint64(b)
	c.high = binary.LittleEndian.Uint64(b[8:])
	return nil
}

func (c Uint128) String() string {
	if c.IsZero() {
		return "0"
	}
	if c.high == 0 {
		return strconv.FormatUint(c.low, 10)
	}

	buf := []byte("0000000000000000000000000000000000000000") // log10(2^128) < 40
	for i := len(buf); ; i -= 19 {
		q, r := c.div64(1e19) // largest power of 10 that fits in a uint64
		var n int
		for ; r != 0; r /= 10 {
			n++
			buf[i-n] += byte(r % 10)
		}
		if q.IsZero() {
			return string(buf[i-n:])
		}
		c = q
	}
}

func (c Uint128) div64(d uint64) (q Uint128, r uint64) {
	if c.high < d {
		q.low, r = bits.Div64(c.high, c.low, d)
	} else {
		q.high, r = bits.Div64(0, c.high, d)
		q.low, r = bits.Div64(r, c.low, d)
	}
	return q, r
}
