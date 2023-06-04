// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"

	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/msgp"
)

type client struct {
	xhttp.Retry
}

type ForwardRequest struct {
	NodeID    NodeID
	EventType uint
	Event     []byte
}

func (r *ForwardRequest) MarshalMsg() (msgp.ForwardRequest, error) {
	return msgp.ForwardRequest{
		NodeID:    uint64(r.NodeID),
		EventType: r.EventType,
		Event:     r.Event,
	}, nil
}

func (r *ForwardRequest) UnmarshalMsg(v *msgp.ForwardRequest) error {
	r.NodeID = NodeID(v.NodeID)
	r.EventType = v.EventType
	r.Event = v.Event
	return nil
}

func (c *client) Forward(ctx context.Context, addr NodeAddr, req ForwardRequest) error {
	const (
		Scheme  = "https://"
		APIPath = "/v1/cluster/rpc/forward"
	)

	body, err := msgp.Marshal[msgp.ForwardRequest](&req)
	if err != nil {
		return err
	}

	url, err := url.JoinPath(Scheme+addr.String(), APIPath)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return err
	}
	resp, err := c.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

type ReplicationRequest struct {
	NodeID    NodeID
	Commit    uint128
	Term      uint128
	EventType uint
	Event     []byte
}

func (r *ReplicationRequest) MarshalMsg() (msgp.ReplicationRequest, error) {
	commit, err := r.Commit.MarshalMsg()
	if err != nil {
		return msgp.ReplicationRequest{}, err
	}
	term, err := r.Term.MarshalMsg()
	if err != nil {
		return msgp.ReplicationRequest{}, err
	}
	return msgp.ReplicationRequest{
		NodeID:    uint64(r.NodeID),
		Commit:    commit,
		Term:      term,
		EventType: r.EventType,
		Event:     r.Event,
	}, nil
}

func (r *ReplicationRequest) UnmarshalMsg(v *msgp.ReplicationRequest) error {
	var commit, term uint128
	if err := commit.UnmarshalMsg(&v.Commit); err != nil {
		return err
	}
	if err := term.UnmarshalMsg(&v.Term); err != nil {
		return err
	}

	r.NodeID = NodeID(v.NodeID)
	r.Commit = commit
	r.Term = term
	r.EventType = v.EventType
	r.Event = v.Event
	return nil
}

func (c *client) Replicate(ctx context.Context, addr NodeAddr, req ReplicationRequest) error {
	const (
		Scheme  = "https://"
		APIPath = "/v1/cluster/rpc/replicate"
	)

	body, err := msgp.Marshal[msgp.ReplicationRequest](&req)
	if err != nil {
		return err
	}

	url, err := url.JoinPath(Scheme+addr.String(), APIPath)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return err
	}
	resp, err := c.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

type VoteRequest struct {
	NodeID        NodeID
	Commit        uint128
	Term          uint128
	ElectionRound uint64
}

func (r *VoteRequest) MarshalMsg() (msgp.VoteRequest, error) {
	commit, err := r.Commit.MarshalMsg()
	if err != nil {
		return msgp.VoteRequest{}, err
	}
	term, err := r.Term.MarshalMsg()
	if err != nil {
		return msgp.VoteRequest{}, err
	}
	return msgp.VoteRequest{
		NodeID:        uint64(r.NodeID),
		Commit:        commit,
		Term:          term,
		ElectionRound: r.ElectionRound,
	}, nil
}

func (r *VoteRequest) UnmarshalMsg(v *msgp.VoteRequest) error {
	var commit, term uint128
	if err := commit.UnmarshalMsg(&v.Commit); err != nil {
		return err
	}
	if err := term.UnmarshalMsg(&v.Term); err != nil {
		return err
	}

	r.NodeID = NodeID(v.NodeID)
	r.Commit = commit
	r.Term = term
	r.ElectionRound = v.ElectionRound
	return nil
}

func (c *client) RequestVote(ctx context.Context, addr NodeAddr, req VoteRequest) error {
	const (
		Scheme  = "https://"
		APIPath = "/v1/cluster/rpc/vote"
	)

	body, err := msgp.Marshal[msgp.VoteRequest](&req)
	if err != nil {
		return err
	}
	url, err := url.JoinPath(Scheme+addr.String(), APIPath)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return err
	}
	resp, err := c.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}
