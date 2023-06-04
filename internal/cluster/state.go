// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"github.com/minio/kes/internal/msgp"
	num "github.com/minio/kes/internal/uint128"
)

type uint128 = num.Uint128 // more ergonomic use of usigned 128 bit integer

type State struct {
	Term          uint128
	Commit        uint128
	ElectionRound uint64

	EventType uint
	Event     []byte
}

func (s *State) MarshalMsg() (msgp.ClusterState, error) {
	term, err := s.Term.MarshalMsg()
	if err != nil {
		return msgp.ClusterState{}, err
	}
	commit, err := s.Commit.MarshalMsg()
	if err != nil {
		return msgp.ClusterState{}, err
	}
	return msgp.ClusterState{
		Term:      term,
		Commit:    commit,
		Round:     s.ElectionRound,
		EventType: s.EventType,
		Event:     s.Event,
	}, nil
}

func (s *State) UnmarshalMsg(v *msgp.ClusterState) error {
	var term, commit uint128
	if err := term.UnmarshalMsg(&v.Term); err != nil {
		return err
	}
	if err := commit.UnmarshalMsg(&v.Commit); err != nil {
		return err
	}

	s.Term = term
	s.Commit = commit
	s.ElectionRound = v.Round
	s.EventType = v.EventType
	s.Event = v.Event
	return nil
}
