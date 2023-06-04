// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package msgp

import "time"

//go:generate msgp

type ClusterState struct {
	Commit    Uint128 `msg:"0"`
	Term      Uint128 `msg:"1"`
	Round     uint64  `msg:"2"`
	EventType uint    `msg:"3"`
	Event     []byte  `msg:"4"`
}

type EncryptedRootKey struct {
	Ciphertexts map[string][]byte `msg:"0"`
}

type Enclave struct {
	Key       SecretKey `msg:"0"`
	Admins    []string  `msg:"1"`
	CreatedAt time.Time `msg:"2"`
	CreatedBy string    `msg:"3"`
}

type EnclaveInfo struct {
	Key       SecretKey `msg:"0"`
	CreatedAt time.Time `msg:"1"`
	CreatedBy string    `msg:"2"`
}

type ChangeClusterMembersEvent struct {
	Members map[string]string `msg:"0"`
}

type CreateEnclaveEvent struct {
	Name      string    `msg:"0"`
	Key       SecretKey `msg:"1"`
	CreatedAt time.Time `msg:"2"`
	CreatedBy string    `msg:"3"`
}

type DeleteEnclaveEvent struct {
	Name string `msg:"0"`
}

type CreateSecretKeyEvent struct {
	Enclave   string    `msg:"0"`
	Name      string    `msg:"1"`
	Key       SecretKey `msg:"2"`
	CreatedAt time.Time `msg:"3"`
	CreatedBy string    `msg:"4"`
}

type DeleteKeyEvent struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

type CreateSecretEvent struct {
	Enclave    string    `msg:"0"`
	Name       string    `msg:"1"`
	Secret     []byte    `msg:"2"`
	SecretType uint      `msg:"3"`
	CreatedAt  time.Time `msg:"4"`
	CreatedBy  string    `msg:"5"`
}

type DeleteSecretEvent struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

type DeleteSecretVersionEvent struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
	Version uint32 `msg:"2"`
}

type CreatePolicyEvent struct {
	Enclave   string              `msg:"0"`
	Name      string              `msg:"1"`
	Allow     map[string]struct{} `msg:"2"`
	Deny      map[string]struct{} `msg:"3"`
	CreatedAt time.Time           `msg:"4"`
	CreatedBy string              `msg:"5"`
}

type DeletePolicyEvent struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

type CreateIdentityEvent struct {
	Enclave   string        `msg:"0"`
	Identity  string        `msg:"1"`
	Policy    string        `msg:"2"`
	IsAdmin   bool          `msg:"3"`
	TTL       time.Duration `msg:"4"`
	ExpiresAt time.Time     `msg:"5"`
	CreatedAt time.Time     `msg:"6"`
	CreatedBy string        `msg:"7"`
}

type DeleteIdentityEvent struct {
	Enclave  string `msg:"0"`
	Identity string `msg:"1"`
}

type ReplicationRequest struct {
	NodeID    uint64  `msg:"0"`
	Commit    Uint128 `msg:"1"`
	Term      Uint128 `msg:"2"`
	EventType uint    `msg:"3"`
	Event     []byte  `msg:"4"`
}

type ForwardRequest struct {
	NodeID    uint64 `msg:"0"`
	EventType uint   `msg:"1"`
	Event     []byte `msg:"2"`
}

type VoteRequest struct {
	NodeID        uint64  `msg:"0"`
	Commit        Uint128 `msg:"1"`
	Term          Uint128 `msg:"2"`
	ElectionRound uint64  `msg:"3"`
}
