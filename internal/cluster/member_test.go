// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import "testing"

func TestMemberSet_Add(t *testing.T) {
	set := MemberSet{}
	for i, test := range addMemberSetTests {
		id, ok := set.Add(test.Addr)
		if ok && !test.Added {
			t.Fatalf("Test %d: failed to add addr '%v' to member set", i, test.Addr)
		}
		if !ok && test.Added {
			t.Fatalf("Test %d: added addr '%v' to member set", i, test.Addr)
		}
		if ok && id != test.ID {
			t.Fatalf("Test %d: assigned incorrect ID to addr '%v': got '%d' - want '%d'", i, test.Addr, id, test.ID)
		}
	}
}

func TestMemberSet_Lookup(t *testing.T) {
	for i, test := range lookupMemberSetTests {
		id, ok := test.Members.Lookup(test.Addr)
		if ok && !test.Lookup {
			t.Fatalf("Test %d: failed to lookup addr '%v'", i, test.Addr)
		}
		if !ok && test.Lookup {
			t.Fatalf("Test %d: found addr '%v'", i, test.Addr)
		}
		if ok && id != test.ID {
			t.Fatalf("Test %d: addr '%v' has incorrect ID: got '%d' - want '%d'", i, test.Addr, id, test.ID)
		}
	}
}

var addMemberSetTests = []struct {
	ID    NodeID
	Added bool
	Addr  NodeAddr
}{
	{ID: 0, Added: true, Addr: mustParseNodeAddr("127.0.0.1:7373")},  // 0
	{ID: 1, Added: true, Addr: mustParseNodeAddr("127.0.0.1:7374")},  // 1
	{ID: 0, Added: false, Addr: mustParseNodeAddr("127.0.0.1:7373")}, // 2
	{ID: 0, Added: false, Addr: mustParseNodeAddr("localhost:7373")}, // 3
	{ID: 2, Added: true, Addr: mustParseNodeAddr("10.1.2.3:443")},    // 4
}

var lookupMemberSetTests = []struct {
	Members MemberSet
	ID      NodeID
	Lookup  bool
	Addr    NodeAddr
}{
	{ // 0
		Members: MemberSet{},
		Addr:    mustParseNodeAddr("127.0.0.1:7373"),
	},

	{ // 1
		Members: MemberSet{
			0: mustParseNodeAddr("127.0.0.1:7373"),
		},
		Addr: mustParseNodeAddr("10.1.2.3:7373"),
	},

	{ // 2
		Members: MemberSet{
			0: mustParseNodeAddr("127.0.0.1:7373"),
			1: mustParseNodeAddr("10.1.2.3:7373"),
		},
		ID:     1,
		Lookup: true,
		Addr:   mustParseNodeAddr("10.1.2.3:7373"),
	},

	{ // 3
		Members: MemberSet{
			0: mustParseNodeAddr("127.0.0.1:7373"),
			1: mustParseNodeAddr("10.1.2.3:7373"),
		},
		ID:     0,
		Lookup: true,
		Addr:   mustParseNodeAddr("localhost:7373"),
	},
}

func mustParseNodeAddr(s string) NodeAddr {
	addr, err := ParseNodeAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
