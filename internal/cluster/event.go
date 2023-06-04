// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/hashset"
	"github.com/minio/kes/internal/msgp"
	bolt "go.etcd.io/bbolt"
)

type Event interface {
	Apply(*Node, *bolt.Tx) error

	Type() uint

	MarshalBinary() ([]byte, error)

	UnmarshalBinary([]byte) error
}

const (
	EventTypeNop = iota
	EventTypeChangeMembers

	EventTypeCreateEnclave = 100 + iota
	EventTypeDeleteEnclave

	EventTypeCreateSecretKeyRing = 200 + iota
	EventTypeDeleteSecretKeyRing

	EventTypeCreateSecret = 300 + iota
	EventTypeDeleteSecret
	EventTypeDeleteSecretVersion

	EventTypeCreateIdentity = 400 + iota
	EventTypeUpdateIdentity
	EventTypeDeleteIdentity

	EventTypeCreatePolicy = 500 + iota
	EventTypeDeletePolicy
)

func DecodeEvent(eventType uint, b []byte) (Event, error) {
	var event Event
	switch eventType {
	// case EventTypeNop:
	// event = new(NopEvent)

	case EventTypeChangeMembers:
		event = new(ChangeMembersEvent)

	case EventTypeCreateEnclave:
		event = new(CreateEnclaveEvent)
	case EventTypeDeleteEnclave:
		event = new(DeleteEnclaveEvent)

	case EventTypeCreateSecretKeyRing:
		event = new(CreateSecretKeyRingEvent)
	case EventTypeDeleteSecretKeyRing:
		event = new(DeleteSecretKeyRing)

	case EventTypeCreateSecret:
		event = new(CreateSecretEvent)
	case EventTypeDeleteSecret:
		event = new(DeleteSecretEvent)

	case EventTypeCreateIdentity:
		event = new(CreateIdentityEvent)
	case EventTypeDeleteIdentity:
		event = new(DeleteIdentityEvent)

	case EventTypeCreatePolicy:
		event = new(CreatePolicyEvent)
	case EventTypeDeletePolicy:
		event = new(DeletePolicyEvent)

	default:
		return nil, kes.NewError(http.StatusBadRequest, "cluster: unknown event type '"+strconv.Itoa(int(eventType))+"'")
	}

	if err := event.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return event, nil
}

type ChangeMembersEvent struct {
	Members MemberSet
}

var _ Event = (*ChangeMembersEvent)(nil)

func (e *ChangeMembersEvent) Apply(node *Node, tx *bolt.Tx) error {
	filename := filepath.Join(node.path, ".cluster.json")
	if err := writeMembers(filename, e.Members); err != nil {
		return err
	}

	id, ok := e.Members.Lookup(node.config.Addr)
	if !ok {
		node.shutdown.Store(true)
		return nil
	}

	node.self = id
	node.members = e.Members.Clone()
	return nil
}

func (*ChangeMembersEvent) Type() uint { return EventTypeChangeMembers }

func (e *ChangeMembersEvent) MarshalMsg() (msgp.ChangeClusterMembersEvent, error) {
	members := make(map[string]string, len(e.Members))
	for id, addr := range e.Members {
		members[strconv.FormatUint(uint64(id), 10)] = addr.String()
	}
	return msgp.ChangeClusterMembersEvent{
		Members: members,
	}, nil
}

func (e *ChangeMembersEvent) UnmarshalMsg(v *msgp.ChangeClusterMembersEvent) error {
	members := make(map[NodeID]NodeAddr, len(v.Members))
	for strID, addr := range v.Members {
		id, err := strconv.ParseUint(strID, 10, 64)
		if err != nil {
			return err
		}
		members[NodeID(id)], err = ParseNodeAddr(addr)
		if err != nil {
			return err
		}
	}
	e.Members = members
	return nil
}

func (e *ChangeMembersEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.ChangeClusterMembersEvent](e)
}

func (e *ChangeMembersEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.ChangeClusterMembersEvent](b, e)
}

type CreateEnclaveEvent struct {
	Name      string
	Key       crypto.SecretKey
	CreatedAt time.Time
	CreatedBy kes.Identity
}

var _ Event = (*CreateEnclaveEvent)(nil)

func (e *CreateEnclaveEvent) Apply(node *Node, tx *bolt.Tx) error {
	return createEnclave(tx, node.rootKey, e.Name, &Enclave{
		Key:       e.Key,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy,
	})
}

func (e *CreateEnclaveEvent) Type() uint { return EventTypeCreateEnclave }

func (e *CreateEnclaveEvent) MarshalMsg() (msgp.CreateEnclaveEvent, error) {
	key, err := e.Key.MarshalMsg()
	if err != nil {
		return msgp.CreateEnclaveEvent{}, err
	}
	return msgp.CreateEnclaveEvent{
		Name:      e.Name,
		Key:       key,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy.String(),
	}, nil
}

func (e *CreateEnclaveEvent) UnmarshalMsg(v *msgp.CreateEnclaveEvent) error {
	var key crypto.SecretKey
	if err := key.UnmarshalMsg(&v.Key); err != nil {
		return err
	}

	e.Name = v.Name
	e.Key = key
	e.CreatedAt = v.CreatedAt
	e.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

func (e *CreateEnclaveEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.CreateEnclaveEvent](e)
}

func (e *CreateEnclaveEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.CreateEnclaveEvent](b, e)
}

type DeleteEnclaveEvent struct {
	Name string
}

var _ Event = (*DeleteEnclaveEvent)(nil)

func (e *DeleteEnclaveEvent) Apply(_ *Node, tx *bolt.Tx) error { return deleteEnclave(tx, e.Name) }

func (*DeleteEnclaveEvent) Type() uint { return EventTypeDeleteEnclave }

func (e *DeleteEnclaveEvent) MarshalMsg() (msgp.DeleteEnclaveEvent, error) {
	return msgp.DeleteEnclaveEvent{
		Name: e.Name,
	}, nil
}

func (e *DeleteEnclaveEvent) UnmarshalMsg(v *msgp.DeleteEnclaveEvent) error {
	e.Name = v.Name
	return nil
}

func (e *DeleteEnclaveEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.DeleteEnclaveEvent](e)
}

func (e *DeleteEnclaveEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.DeleteEnclaveEvent](b, e)
}

type CreateSecretKeyRingEvent struct {
	Enclave   string
	Name      string
	Key       crypto.SecretKey
	CreatedAt time.Time
	CreatedBy kes.Identity
}

var _ Event = (*CreateSecretKeyRingEvent)(nil)

func (e *CreateSecretKeyRingEvent) Apply(node *Node, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, node.rootKey, e.Enclave)
	if err != nil {
		return err
	}
	var ring crypto.SecretKeyRing
	if err = ring.Add(crypto.SecretKeyVersion{
		Key:       e.Key,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy,
	}); err != nil {
		return err
	}
	return createSecretKeyRing(tx, enc.Key, e.Enclave, e.Name, &ring)
}

func (*CreateSecretKeyRingEvent) Type() uint { return EventTypeCreateSecretKeyRing }

func (e *CreateSecretKeyRingEvent) MarshalMsg() (msgp.CreateSecretKeyEvent, error) {
	key, err := e.Key.MarshalMsg()
	if err != nil {
		return msgp.CreateSecretKeyEvent{}, err
	}
	return msgp.CreateSecretKeyEvent{
		Enclave:   e.Enclave,
		Name:      e.Name,
		Key:       key,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy.String(),
	}, nil
}

func (e *CreateSecretKeyRingEvent) UnmarshalMsg(v *msgp.CreateSecretKeyEvent) error {
	var key crypto.SecretKey
	if err := key.UnmarshalMsg(&v.Key); err != nil {
		return err
	}

	e.Enclave = v.Enclave
	e.Name = v.Name
	e.Key = key
	e.CreatedAt = v.CreatedAt
	e.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

func (e *CreateSecretKeyRingEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.CreateSecretKeyEvent](e)
}

func (e *CreateSecretKeyRingEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.CreateSecretKeyEvent](b, e)
}

type DeleteSecretKeyRing struct {
	Enclave string
	Name    string
}

var _ Event = (*DeleteSecretKeyRing)(nil)

func (e *DeleteSecretKeyRing) Apply(_ *Node, tx *bolt.Tx) error {
	return deleteSecretKeyRing(tx, e.Enclave, e.Name)
}

func (*DeleteSecretKeyRing) Type() uint { return EventTypeDeleteSecretKeyRing }

func (e *DeleteSecretKeyRing) MarshalMsg() (msgp.DeleteKeyEvent, error) {
	return msgp.DeleteKeyEvent{
		Enclave: e.Enclave,
		Name:    e.Name,
	}, nil
}

func (e *DeleteSecretKeyRing) UnmarshalMsg(v *msgp.DeleteKeyEvent) error {
	e.Enclave = v.Enclave
	e.Name = v.Name
	return nil
}

func (e *DeleteSecretKeyRing) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.DeleteKeyEvent](e)
}

func (e *DeleteSecretKeyRing) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.DeleteKeyEvent](b, e)
}

type CreateSecretEvent struct {
	Enclave    string
	Name       string
	Secret     []byte
	SecretType crypto.SecretType
	CreatedAt  time.Time
	CreatedBy  kes.Identity
}

func (e *CreateSecretEvent) Apply(node *Node, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, node.rootKey, e.Enclave)
	if err != nil {
		return err
	}
	var secret crypto.Secret
	if err = secret.Add(crypto.SecretVersion{
		Value:     e.Secret,
		Type:      e.SecretType,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy,
	}); err != nil {
		return err
	}
	return createSecret(tx, enc.Key, e.Enclave, e.Name, &secret)
}

func (*CreateSecretEvent) Type() uint { return EventTypeCreateSecret }

func (e *CreateSecretEvent) MarshalMsg() (msgp.CreateSecretEvent, error) {
	return msgp.CreateSecretEvent{
		Enclave:    e.Enclave,
		Name:       e.Name,
		Secret:     e.Secret,
		SecretType: uint(e.SecretType),
		CreatedAt:  e.CreatedAt,
		CreatedBy:  e.CreatedBy.String(),
	}, nil
}

func (e *CreateSecretEvent) UnmarshalMsg(v *msgp.CreateSecretEvent) error {
	e.Enclave = v.Enclave
	e.Name = v.Name
	e.Secret = v.Secret
	e.SecretType = crypto.SecretType(v.SecretType)
	e.CreatedAt = v.CreatedAt
	e.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

func (e *CreateSecretEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.CreateSecretEvent](e)
}

func (e *CreateSecretEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.CreateSecretEvent](b, e)
}

type DeleteSecretEvent struct {
	Enclave string
	Name    string
}

func (e *DeleteSecretEvent) Apply(_ *Node, tx *bolt.Tx) error {
	return deleteSecret(tx, e.Enclave, e.Name)
}

func (*DeleteSecretEvent) Type() uint { return EventTypeDeleteSecret }

func (e *DeleteSecretEvent) MarshalMsg() (msgp.DeleteSecretEvent, error) {
	return msgp.DeleteSecretEvent{
		Enclave: e.Enclave,
		Name:    e.Name,
	}, nil
}

func (e *DeleteSecretEvent) UnmarshalMsg(v *msgp.DeleteSecretEvent) error {
	e.Enclave = v.Enclave
	e.Name = v.Name
	return nil
}

func (e *DeleteSecretEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.DeleteSecretEvent](e)
}

func (e *DeleteSecretEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.DeleteSecretEvent](b, e)
}

type CreateIdentityEvent struct {
	Enclave   string
	Identity  kes.Identity
	IsAdmin   bool
	Policy    string
	TTL       time.Duration
	ExpiresAt time.Time
	CreatedAt time.Time
	CreatedBy kes.Identity
}

func (e *CreateIdentityEvent) Apply(node *Node, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, node.rootKey, e.Enclave)
	if err != nil {
		return err
	}
	return createIdentity(tx, enc.Key, e.Enclave, e.Identity, &auth.Identity{
		Identity:  e.Identity,
		Policy:    e.Policy,
		IsAdmin:   e.IsAdmin,
		Children:  hashset.Set[kes.Identity]{},
		TTL:       e.TTL,
		ExpiresAt: e.ExpiresAt,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy,
	})
}

func (*CreateIdentityEvent) Type() uint { return EventTypeCreateIdentity }

func (e *CreateIdentityEvent) MarshalMsg() (msgp.CreateIdentityEvent, error) {
	return msgp.CreateIdentityEvent{
		Enclave:   e.Enclave,
		Identity:  e.Identity.String(),
		Policy:    e.Policy,
		IsAdmin:   e.IsAdmin,
		TTL:       e.TTL,
		ExpiresAt: e.ExpiresAt,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy.String(),
	}, nil
}

func (e *CreateIdentityEvent) UnmarshalMsg(v *msgp.CreateIdentityEvent) error {
	e.Enclave = v.Enclave
	e.Identity = kes.Identity(v.Identity)
	e.Policy = v.Policy
	e.IsAdmin = v.IsAdmin
	e.TTL = v.TTL
	e.ExpiresAt = v.ExpiresAt
	e.CreatedAt = v.CreatedAt
	e.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

func (e *CreateIdentityEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.CreateIdentityEvent](e)
}

func (e *CreateIdentityEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.CreateIdentityEvent](b, e)
}

type DeleteIdentityEvent struct {
	Enclave  string
	Identity kes.Identity
}

func (e *DeleteIdentityEvent) Apply(node *Node, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, node.rootKey, e.Enclave)
	if err != nil {
		return err
	}

	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(e.Enclave)); b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbIdentityBucket)); b == nil {
		return nil
	}
	return deleteIdentity(b, enc.Key, e.Enclave, e.Identity)
}

func (*DeleteIdentityEvent) Type() uint { return EventTypeDeleteIdentity }

func (e *DeleteIdentityEvent) MarshalMsg() (msgp.DeleteIdentityEvent, error) {
	return msgp.DeleteIdentityEvent{
		Enclave:  e.Enclave,
		Identity: string(e.Identity),
	}, nil
}

func (e *DeleteIdentityEvent) UnmarshalMsg(v *msgp.DeleteIdentityEvent) error {
	e.Enclave = v.Enclave
	e.Identity = kes.Identity(v.Identity)
	return nil
}

func (e *DeleteIdentityEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.DeleteIdentityEvent](e)
}

func (e *DeleteIdentityEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.DeleteIdentityEvent](b, e)
}

type CreatePolicyEvent struct {
	Enclave   string
	Name      string
	Allow     map[string]auth.Rule
	Deny      map[string]auth.Rule
	CreatedAt time.Time
	CreatedBy kes.Identity
}

func (e *CreatePolicyEvent) Apply(node *Node, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, node.rootKey, e.Enclave)
	if err != nil {
		return err
	}
	return createPolicy(tx, enc.Key, e.Enclave, e.Name, &auth.Policy{
		Allow:     e.Allow,
		Deny:      e.Deny,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy,
	})
}

func (*CreatePolicyEvent) Type() uint { return EventTypeCreatePolicy }

func (e *CreatePolicyEvent) MarshalMsg() (msgp.CreatePolicyEvent, error) {
	return msgp.CreatePolicyEvent{
		Enclave:   e.Enclave,
		Name:      e.Name,
		Allow:     e.Allow,
		Deny:      e.Deny,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy.String(),
	}, nil
}

func (e *CreatePolicyEvent) UnmarshalMsg(v *msgp.CreatePolicyEvent) error {
	e.Enclave = v.Enclave
	e.Name = v.Name
	e.Allow = v.Allow
	e.Deny = v.Deny
	e.CreatedAt = v.CreatedAt
	e.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

func (e *CreatePolicyEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.CreatePolicyEvent](e)
}

func (e *CreatePolicyEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.CreatePolicyEvent](b, e)
}

type DeletePolicyEvent struct {
	Enclave string
	Name    string
}

func (e *DeletePolicyEvent) Apply(_ *Node, tx *bolt.Tx) error {
	return deletePolicy(tx, e.Enclave, e.Name)
}

func (*DeletePolicyEvent) Type() uint { return EventTypeDeletePolicy }

func (e *DeletePolicyEvent) MarshalMsg() (msgp.DeletePolicyEvent, error) {
	return msgp.DeletePolicyEvent{
		Enclave: e.Enclave,
		Name:    e.Name,
	}, nil
}

func (e *DeletePolicyEvent) UnmarshalMsg(v *msgp.DeletePolicyEvent) error {
	e.Enclave = v.Enclave
	e.Name = v.Name
	return nil
}

func (e *DeletePolicyEvent) MarshalBinary() ([]byte, error) {
	return msgp.Marshal[msgp.DeletePolicyEvent](e)
}

func (e *DeletePolicyEvent) UnmarshalBinary(b []byte) error {
	return msgp.Unmarshal[msgp.DeletePolicyEvent](b, e)
}
