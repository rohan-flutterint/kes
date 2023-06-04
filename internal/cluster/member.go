// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"encoding/json"
	"os"
	"strconv"
)

type MemberSet map[NodeID]NodeAddr

func (m MemberSet) Add(addr NodeAddr) (NodeID, bool) {
	for id, member := range m {
		if addr.equal(member) {
			return id, false
		}
	}

	for i := 0; i < len(m); i++ {
		id := NodeID(i)
		if _, ok := m[id]; !ok {
			m[id] = addr
			return id, true
		}
	}

	id := NodeID(len(m))
	m[id] = addr
	return id, true
}

func (m MemberSet) Lookup(addr NodeAddr) (NodeID, bool) {
	for id, member := range m {
		if addr.equal(member) {
			return id, true
		}
	}
	return 0, false
}

func (m MemberSet) Remove(addr NodeAddr) (NodeID, bool) {
	if len(m) <= 1 {
		return 0, false
	}

	for id, member := range m {
		if addr.equal(member) {
			delete(m, id)
			return id, true
		}
	}
	return 0, false
}

func (m MemberSet) Clone() MemberSet {
	if m == nil {
		return nil
	}

	members := make(MemberSet, len(m))
	for id, member := range m {
		members[id] = member
	}
	return members
}

func (m MemberSet) MarshalJSON() ([]byte, error) {
	members := make(map[string]string, len(m))
	for id, addr := range m {
		members[strconv.FormatUint(uint64(id), 10)] = addr.String()
	}
	return json.Marshal(members)
}

func (m *MemberSet) UnmarshalJSON(data []byte) error {
	v := make(map[string]string)
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	members := make(map[NodeID]NodeAddr, len(v))
	for k, s := range v {
		id, err := strconv.ParseUint(k, 10, 64)
		if err != nil {
			return err
		}
		addr, err := ParseNodeAddr(s)
		if err != nil {
			return err
		}
		members[NodeID(id)] = addr

	}
	*m = members
	return nil
}

func readMembers(filename string) (MemberSet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var m MemberSet
	if err := json.NewDecoder(file).Decode(&m); err != nil {
		return nil, err
	}
	return m, file.Close()
}

func writeMembers(filename string, m MemberSet) error {
	tmp := filename + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_SYNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	if err = json.NewEncoder(file).Encode(m); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filename)
}
