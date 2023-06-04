// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"bytes"

	"github.com/minio/kes/internal/msgp"
)

type EncryptedRootKey struct {
	ciphertexts map[string][]byte
}

func (e *EncryptedRootKey) Get(provider string) ([]byte, bool) {
	c, ok := e.ciphertexts[provider]
	if !ok {
		return nil, false
	}

	ciphertext := make([]byte, 0, len(c))
	return append(ciphertext, c...), true
}

func (e *EncryptedRootKey) Set(provider string, ciphertext []byte) {
	if e.ciphertexts == nil {
		e.ciphertexts = make(map[string][]byte)
	}
	e.ciphertexts[provider] = bytes.Clone(ciphertext)
}

func (e *EncryptedRootKey) MarshalMsg() (msgp.EncryptedRootKey, error) {
	return msgp.EncryptedRootKey{
		Ciphertexts: e.ciphertexts,
	}, nil
}

func (e *EncryptedRootKey) UnmarshalMsg(v *msgp.EncryptedRootKey) error {
	e.ciphertexts = make(map[string][]byte, len(v.Ciphertexts))
	for k, c := range v.Ciphertexts {
		e.ciphertexts[k] = bytes.Clone(c)
	}
	return nil
}
