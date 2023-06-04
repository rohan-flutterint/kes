// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/crypto"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/msgp"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sync/errgroup"
)

type NodeType uint

const (
	Follower NodeType = iota
	Candidate
	Leader
)

type NodeID uint64

type NodeConfig struct {
	Addr NodeAddr

	Admin kes.Identity

	SealKey *crypto.SealKey

	APIKey kes.APIKey

	RootCAs *x509.CertPool
}

func (n *NodeConfig) Clone() *NodeConfig {
	if n == nil {
		return nil
	}
	return &NodeConfig{
		Addr:    n.Addr,
		Admin:   n.Admin,
		SealKey: n.SealKey,
		APIKey:  n.APIKey,
		RootCAs: n.RootCAs,
	}
}

type Node struct {
	path string

	db      *bolt.DB
	rpc     atomic.Pointer[client]
	metrics atomic.Pointer[metric.Metrics]

	mu           sync.Mutex
	members      MemberSet
	config       *NodeConfig
	rootKey      crypto.SecretKey
	kind         NodeType
	state        State
	self, leader NodeID

	heartbeatTicker   atomic.Pointer[time.Ticker]
	electionTicker    atomic.Pointer[time.Ticker]
	eventReplicated   atomic.Bool
	heartbeatReceived atomic.Bool

	ctx      context.Context
	stop     context.CancelFunc
	started  atomic.Bool
	shutdown atomic.Bool
}

func StartNode(ctx context.Context, path string, config *NodeConfig) (*Node, error) {
	n := new(Node)
	if err := n.Start(ctx, path, config.Clone()); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *Node) DB() *bolt.DB {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.db
}

func (n *Node) Metrics() *metric.Metrics { return n.metrics.Load() }

func (n *Node) RPC() *client {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.rpc.Load()
}

func (n *Node) Config() *NodeConfig {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.config.Clone()
}

func (n *Node) MemberSet() MemberSet {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.members.Clone()
}

func (n *Node) Leader() NodeID {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.leader
}

func (n *Node) IsAdmin(identity kes.Identity) bool {
	return n.config.Admin == identity
}

func (n *Node) IsPeer(identity kes.Identity) bool {
	return n.config.APIKey.Identity() == identity
}

func (n *Node) GetEnclave(ctx context.Context, name string) (*Enclave, error) {
	if !n.started.Load() {
		return nil, ErrNodeClosed
	}

	var enc *Enclave
	err := n.db.View(func(tx *bolt.Tx) error {
		var err error
		enc, err = readEnclave(tx, n.rootKey, name)
		return err
	})
	return enc, err
}

func (n *Node) ListEnclaves(ctx context.Context, prefix string) ([]string, string, error) {
	if !n.started.Load() {
		return nil, "", ErrNodeClosed
	}

	const BatchSize = 250
	var names []string
	if err := n.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			prefix = ""
			return nil
		}
		names, prefix = listBuckets(b, prefix, BatchSize)
		return nil
	}); err != nil {
		return nil, "", err
	}
	return names, prefix, nil
}

func (n *Node) GetSecretKeyRing(ctx context.Context, enclave, name string) (*crypto.SecretKeyRing, error) {
	if !n.started.Load() {
		return nil, ErrNodeClosed
	}

	var ring *crypto.SecretKeyRing
	err := n.db.View(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, n.rootKey, enclave)
		if err != nil {
			return err
		}
		ring, err = readSecretKeyRing(tx, enc.Key, enclave, name)
		return err
	})
	return ring, err
}

func (n *Node) ListSecretKeyRings(ctx context.Context, enclave, prefix string) ([]string, string, error) {
	if !n.started.Load() {
		return nil, "", ErrNodeClosed
	}

	const BatchSize = 250
	var names []string
	if err := n.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		if b = b.Bucket([]byte(enclave)); b == nil {
			return kes.ErrEnclaveNotFound
		}
		if b = b.Bucket([]byte(dbSecretKeyBucket)); b == nil {
			prefix = ""
			return nil
		}
		names, prefix = listKeys[string](b, prefix, BatchSize)
		return nil
	}); err != nil {
		return nil, "", err
	}
	return names, prefix, nil
}

func (n *Node) GetSecret(ctx context.Context, enclave, name string) (*crypto.Secret, error) {
	if !n.started.Load() {
		return nil, ErrNodeClosed
	}

	var secret *crypto.Secret
	err := n.db.View(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, n.rootKey, enclave)
		if err != nil {
			return err
		}
		secret, err = readSecret(tx, enc.Key, enclave, name)
		return err
	})
	return secret, err
}

func (n *Node) GetIdentity(ctx context.Context, enclave string, identity kes.Identity) (*auth.Identity, error) {
	if !n.started.Load() {
		return nil, ErrNodeClosed
	}

	var id *auth.Identity
	err := n.db.View(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, n.rootKey, enclave)
		if err != nil {
			return err
		}
		id, err = readIdentity(tx, enc.Key, enclave, identity.String())
		return err
	})
	return id, err
}

func (n *Node) ListIdentities(ctx context.Context, enclave, prefix string) ([]kes.Identity, string, error) {
	if !n.started.Load() {
		return nil, "", ErrNodeClosed
	}

	const BatchSize = 250
	var identities []kes.Identity
	if err := n.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		if b = b.Bucket([]byte(enclave)); b == nil {
			return kes.ErrEnclaveNotFound
		}
		if b = b.Bucket([]byte(dbIdentityBucket)); b == nil {
			prefix = ""
			return nil
		}
		identities, prefix = listKeys[kes.Identity](b, prefix, BatchSize)
		return nil
	}); err != nil {
		return nil, "", err
	}
	return identities, prefix, nil
}

func (n *Node) GetPolicy(ctx context.Context, enclave, name string) (*auth.Policy, error) {
	if !n.started.Load() {
		return nil, ErrNodeClosed
	}

	var policy *auth.Policy
	err := n.db.View(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, n.rootKey, enclave)
		if err != nil {
			return err
		}
		policy, err = readPolicy(tx, enc.Key, enclave, name)
		return err
	})
	return policy, err
}

func (n *Node) ListPolicies(ctx context.Context, enclave, prefix string) ([]string, string, error) {
	if !n.started.Load() {
		return nil, "", ErrNodeClosed
	}

	const BatchSize = 250
	var names []string
	if err := n.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		if b = b.Bucket([]byte(enclave)); b == nil {
			return kes.ErrEnclaveNotFound
		}
		if b = b.Bucket([]byte(dbPolicyBucket)); b == nil {
			prefix = ""
			return nil
		}
		names, prefix = listKeys[string](b, prefix, BatchSize)
		return nil
	}); err != nil {
		return nil, "", err
	}
	return names, prefix, nil
}

func (n *Node) VerifyRequest(r *http.Request) (string, kes.Identity, error) {
	if !n.started.Load() {
		return "", "", ErrNodeClosed
	}

	enclave, err := readEnclaveHeader(r.Header)
	if err != nil {
		return "", "", err
	}
	identity, err := auth.IdentifyRequest(r.TLS)
	if err != nil {
		return "", "", err
	}
	if identity == n.config.Admin {
		return enclave, identity, nil
	}

	var (
		id     *auth.Identity
		policy *auth.Policy
	)
	if err = n.db.View(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, n.rootKey, enclave)
		if err != nil {
			return err
		}
		id, err = readIdentity(tx, enc.Key, enclave, identity.String())
		if err != nil {
			return err
		}
		if !id.IsAdmin {
			policy, err = readPolicy(tx, enc.Key, enclave, id.Policy)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		if errors.Is(err, kes.ErrIdentityNotFound) || errors.Is(err, kes.ErrPolicyNotFound) {
			return "", "", kes.ErrNotAllowed
		}
		return "", "", err
	}
	if id.IsAdmin {
		return enclave, identity, nil
	}
	return enclave, identity, policy.Verify(r)
}

func (n *Node) Start(ctx context.Context, path string, config *NodeConfig) error {
	if n.started.Load() {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.started.Load() {
		return nil
	}

	config = config.Clone()
	if config.APIKey == nil {
		apiKey, err := config.SealKey.GenerateAPIKey(nil)
		if err != nil {
			return err
		}
		config.APIKey = apiKey
	}
	if config.Admin.IsUnknown() {
		config.Admin = config.APIKey.Identity()
	}
	cert, err := kes.GenerateCertificate(config.APIKey, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(5 * 365 * 24 * time.Hour) // 5 years
	})
	if err != nil {
		return err
	}

	members, self, err := initMemberSet(path, config)
	if err != nil {
		return err
	}
	db, rootKey, state, err := initDB(path, config)
	if err != nil {
		db.Close()
		return err
	}

	n.path = path
	n.db = db
	n.members = members
	n.config = config
	n.rootKey = rootKey
	n.kind = Follower
	n.state = state
	n.self, n.leader = self, math.MaxUint64
	n.metrics.Store(metric.New())
	n.rpc.Store(&client{
		Retry: xhttp.Retry{
			Client: http.Client{
				Transport: &http.Transport{
					Proxy:                 http.ProxyFromEnvironment,
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					TLSClientConfig: &tls.Config{
						Certificates: []tls.Certificate{cert},
						RootCAs:      config.RootCAs,
					},
				},
			},
			Delay:  50 * time.Millisecond,
			Jitter: 10 * time.Millisecond,
		},
	})

	n.ctx = ctx
	ctx, n.stop = context.WithCancel(ctx)

	n.heartbeatTicker.Store(time.NewTicker(250 * time.Millisecond))
	n.electionTicker.Store(time.NewTicker(random(1500*time.Millisecond, 2000*time.Millisecond)))
	n.eventReplicated.Store(false)
	n.heartbeatReceived.Store(false)

	go n.heartbeatLoop(ctx)
	go n.electionLoop(ctx)

	n.shutdown.Store(false)
	n.started.Store(true)
	return nil
}

func (n *Node) Restart() error { return n.Start(n.ctx, n.path, n.config) }

func (n *Node) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.started.Load() {
		return ErrNodeClosed
	}

	n.stop()
	err := n.db.Close()

	n.started.Store(false)
	return err
}

func (n *Node) Vote(req VoteRequest) error {
	if !n.started.Load() {
		return ErrNodeClosed
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state.Commit.Greater(req.Commit) {
		return VoteError{
			// StatusCode: raft.VoteOldCommit,
		}
	}
	if n.state.Term.Greater(req.Term) {
		return VoteError{
			// StatusCode: raft.VoteTermExpired,
		}
	}
	if n.state.Term == req.Term && n.state.Commit == req.Commit && n.state.ElectionRound >= req.ElectionRound {
		return VoteError{
			// StatusCode: raft.VoteElectionExpired,
		}
	}

	s := n.state
	s.Term = req.Term
	s.ElectionRound = req.ElectionRound
	if err := n.db.Update(func(tx *bolt.Tx) error { return writeState(tx, n.rootKey, s) }); err != nil {
		return err
	}
	n.state = s
	return nil
}

func (n *Node) Apply(ctx context.Context, event Event) error {
	if !n.started.Load() {
		return ErrNodeClosed
	}

	encEvent, err := event.MarshalBinary()
	if err != nil {
		return err
	}

	n.mu.Lock()
	if n.kind != Leader {
		if n.leader == n.self {
			n.mu.Unlock()

			// This might happen when the node is not able to
			// join a cluster, and therefore, fails to receive
			// replication requests from the leader. If the Node's
			// ID (within the cluster) happens to be 0 - which is
			// also the default value on startup - then the node
			// is in Follower state but the leader ID still points to
			// itself.
			// TODO: log this situation
			return kes.NewError(http.StatusInternalServerError, "cluster: cannot accept request: leader is unknown")
		}
		leader, ok := n.members[n.leader]
		if !ok {
			n.mu.Unlock()

			// TODO: log this situation
			return kes.NewError(http.StatusInternalServerError, "cluster: cannot accept request: no leader")
		}
		self := n.self
		n.mu.Unlock()

		return n.rpc.Load().Forward(ctx, leader, ForwardRequest{
			NodeID:    self,
			EventType: event.Type(),
			Event:     encEvent,
		})
	}
	defer n.mu.Unlock()

	if !n.eventReplicated.Load() {
		self := n.self
		var wg errgroup.Group
		for id, addr := range n.members {
			if id == self {
				continue
			}

			addr, state := addr, n.state
			wg.Go(func() error {
				return n.rpc.Load().Replicate(n.ctx, addr, ReplicationRequest{
					NodeID:    self,
					Commit:    state.Commit,
					Term:      state.Term,
					EventType: state.EventType,
					Event:     state.Event,
				})
			})
		}
		if err := wg.Wait(); err != nil {
			return errors.Join(kes.ErrPartialWrite, err)
		}
	}
	n.eventReplicated.Store(true)
	if n.shutdown.Load() {
		n.stop()
		err := n.db.Close()
		n.started.Store(false)
		return err
	}

	s := n.state
	s.EventType = event.Type()
	s.Event = encEvent
	s.Commit = s.Commit.Inc()
	s.ElectionRound = 0

	if err = n.db.Update(func(tx *bolt.Tx) error {
		if err := event.Apply(n, tx); err != nil {
			return err
		}
		if err := writeState(tx, n.rootKey, s); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}); err != nil {
		return err
	}
	n.eventReplicated.Store(false)
	n.state = s

	self := n.self
	var wg errgroup.Group
	for id, addr := range n.members {
		if id == self {
			continue
		}

		addr, state := addr, n.state
		wg.Go(func() error {
			return n.rpc.Load().Replicate(n.ctx, addr, ReplicationRequest{
				NodeID:    self,
				Commit:    state.Commit,
				Term:      state.Term,
				EventType: state.EventType,
				Event:     state.Event,
			})
		})
	}
	if err := wg.Wait(); err != nil {
		return err
	}
	n.eventReplicated.Store(true)

	if n.shutdown.Load() {
		n.stop()
		err := n.db.Close()
		n.started.Store(false)
		return err
	}
	return nil
}

func (n *Node) Receive(req ReplicationRequest) error {
	if !n.started.Load() {
		return ErrNodeClosed
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state.Term.Greater(req.Term) {
		return ReplicationError{
			// StatusCode: raft.ReplicateTermExpired,
		}
	}
	if n.state.Commit.Greater(req.Commit) {
		return ReplicationError{
			// StatusCode: raft.ReplicateOldCommit,
		}
	}

	n.kind = Follower
	n.leader = req.NodeID
	n.heartbeatReceived.Store(true)
	n.eventReplicated.Store(false)

	if n.state.Commit == req.Commit && n.state.Term == req.Term {
		return nil
	}

	event, err := DecodeEvent(req.EventType, req.Event)
	if err != nil {
		return err
	}

	s := n.state
	s.EventType = req.EventType
	s.Event = req.Event
	s.Term = req.Term
	s.Commit = req.Commit
	s.ElectionRound = 0

	if err := n.db.Update(func(tx *bolt.Tx) error {
		if n.state.Commit != req.Commit {
			if err := event.Apply(n, tx); err != nil {
				return err
			}
		}
		return writeState(tx, n.rootKey, s)
	}); err != nil {
		return err
	}

	n.state = s
	return nil
}

func (n *Node) AddMember(ctx context.Context, addr NodeAddr) error {
	if !n.started.Load() {
		return ErrNodeClosed
	}

	n.mu.Lock()
	config := n.members.Clone()
	config.Add(addr)
	n.mu.Unlock()

	return n.Apply(ctx, &ChangeMembersEvent{
		Members: config,
	})
}

func (n *Node) heartbeatLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.heartbeatTicker.Load().C:
			n.sendHeartbeats()
		}
	}
}

func (n *Node) electionLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.electionTicker.Load().C:
			if !n.heartbeatReceived.CompareAndSwap(true, false) {
				n.requestVotes()
			}
		}
	}
}

func (n *Node) sendHeartbeats() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.kind != Leader {
		return
	}

	self := n.self
	for id, addr := range n.members {
		if id == n.self {
			continue
		}

		addr, state := addr, n.state
		go n.rpc.Load().Replicate(n.ctx, addr, ReplicationRequest{
			NodeID:    self,
			Commit:    state.Commit,
			Term:      state.Term,
			EventType: state.EventType,
			Event:     state.Event,
		})
	}
}

func (n *Node) requestVotes() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(n.members) <= 1 {
		n.kind = Leader
		n.leader = n.self
		return
	}
	if n.kind != Follower {
		return
	}

	n.kind = Candidate
	n.leader = math.MaxUint64

	s := n.state
	s.ElectionRound++
	if err := n.db.Update(func(tx *bolt.Tx) error { return writeState(tx, n.rootKey, s) }); err != nil {
		n.kind = Follower
		return
	}
	n.state = s

	self := n.self
	wg, voteCtx := errgroup.WithContext(n.ctx)
	for id, addr := range n.members {
		if id == self {
			continue
		}

		addr, state := addr, n.state
		wg.Go(func() error {
			return n.rpc.Load().RequestVote(voteCtx, addr, VoteRequest{
				NodeID:        self,
				Commit:        state.Commit,
				Term:          state.Term,
				ElectionRound: state.ElectionRound,
			})
		})
	}
	if err := wg.Wait(); err != nil {
		n.kind = Follower
		return
	}

	s = n.state
	s.Term = s.Term.Inc()
	s.ElectionRound = 0
	if err := n.db.Update(func(tx *bolt.Tx) error { return writeState(tx, n.rootKey, s) }); err != nil {
		n.kind = Follower
		return
	}

	n.kind = Leader
	n.leader = n.self
	n.eventReplicated.Store(false)
}

func initMemberSet(path string, config *NodeConfig) (MemberSet, NodeID, error) {
	filename := filepath.Join(path, ".cluster.json")

	members, err := readMembers(filename)
	if errors.Is(err, os.ErrNotExist) {
		err = writeMembers(filename, map[NodeID]NodeAddr{0: config.Addr})
		if err != nil {
			return nil, 0, err
		}
		members, err = readMembers(filename)
	}
	if err != nil {
		return nil, 0, err
	}

	self, ok := members.Lookup(config.Addr)
	if !ok {
		return nil, 0, fmt.Errorf("cluster: node '%s' is not part of the cluster", config.Addr)
	}
	return members, self, nil
}

func initDB(path string, config *NodeConfig) (*bolt.DB, crypto.SecretKey, State, error) {
	db, err := bolt.Open(filepath.Join(path, "kes.db"), 0o644, &bolt.Options{
		FreelistType: bolt.FreelistMapType,
		Timeout:      5 * time.Second,
	})
	if err != nil {
		return nil, crypto.SecretKey{}, State{}, err
	}

	var (
		rootKey crypto.SecretKey
		state   State
	)
	if err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(dbClusterBucket))
		if err != nil {
			return err
		}

		var encRootKey EncryptedRootKey
		ciphertext := bytes.Clone(b.Get([]byte("root")))
		if ciphertext == nil {
			key, err := crypto.GenerateSecretKey(crypto.AES256, nil)
			if err != nil {
				return err
			}
			plaintext, err := msgp.Marshal[msgp.SecretKey](&key)
			if err != nil {
				return err
			}
			ciphertext, err = config.SealKey.Seal(plaintext)
			if err != nil {
				return err
			}

			encRootKey.Set(config.SealKey.Name(), ciphertext)
			ciphertext, err = msgp.Marshal[msgp.EncryptedRootKey](&encRootKey)
			if err != nil {
				return err
			}
			if err = b.Put([]byte(dbClusterRootKey), bytes.Clone(ciphertext)); err != nil {
				return err
			}
		}

		if err = msgp.Unmarshal[msgp.EncryptedRootKey](ciphertext, &encRootKey); err != nil {
			return err
		}
		ciphertext, ok := encRootKey.Get(config.SealKey.Name())
		if !ok {
			return errors.New("cluster: no encrypted root key for unseal provider '" + config.SealKey.Name() + "' found")
		}
		plaintext, err := config.SealKey.Unseal(ciphertext)
		if err != nil {
			return err
		}
		if err = msgp.Unmarshal[msgp.SecretKey](plaintext, &rootKey); err != nil {
			return err
		}

		s := bytes.Clone(b.Get([]byte(dbClusterStateKey)))
		if s == nil {
			return nil
		}
		s, err = rootKey.Decrypt(s, []byte(dbClusterBucket+"/"+dbClusterStateKey))
		if err != nil {
			return err
		}
		return msgp.Unmarshal[msgp.ClusterState](s, &state)
	}); err != nil {
		db.Close()
		return nil, crypto.SecretKey{}, State{}, err
	}
	return db, rootKey, state, nil
}

func random(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}

	r := mrand.Int63n(int64(max - min))
	return min + time.Duration(r)
}
