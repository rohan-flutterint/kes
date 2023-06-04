// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"net/http"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/msgp"
)

func readEnclaveHeader(h http.Header) (string, error) {
	const EnclaveHeaderKey = "Kes-Enclave"

	v := h.Values(EnclaveHeaderKey)
	if len(v) == 0 {
		return "", kes.NewError(http.StatusBadRequest, "no enclave specified")
	}

	enclave := v[0]
	// TODO: verify enclave name
	return enclave, nil
}

type Enclave struct {
	Key       crypto.SecretKey
	CreatedAt time.Time
	CreatedBy kes.Identity
}

func (e *Enclave) MarshalMsg() (msgp.Enclave, error) {
	key, err := e.Key.MarshalMsg()
	if err != nil {
		return msgp.Enclave{}, err
	}

	return msgp.Enclave{
		Key:       key,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy.String(),
	}, nil
}

func (e *Enclave) UnmarshalMsg(v *msgp.Enclave) error {
	var key crypto.SecretKey
	if err := key.UnmarshalMsg(&v.Key); err != nil {
		return err
	}

	e.Key = key
	e.CreatedAt = v.CreatedAt
	e.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}
