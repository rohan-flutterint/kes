// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"errors"
	"net"
	"strings"
)

func ParseNodeAddr(s string) (NodeAddr, error) {
	switch {
	case strings.HasPrefix(s, "https://"):
		s = strings.TrimPrefix(s, "https://")
	case strings.HasPrefix(s, "http://"):
		s = strings.TrimPrefix(s, "http://")
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return NodeAddr{}, err
	}
	if host == "" {
		return NodeAddr{}, errors.New("cluster: host is empty")
	}

	return NodeAddr{
		host: host,
		port: port,
	}, err
}

type NodeAddr struct {
	host, port string
}

func (NodeAddr) Network() string { return "tcp" }

func (n NodeAddr) String() string { return net.JoinHostPort(n.host, n.port) }

func (n NodeAddr) Host() string { return n.host }

func (n NodeAddr) IsLoopback() bool {
	if n.host == "localhost" {
		return true
	}

	ip := net.ParseIP(n.host)
	return ip != nil && ip.IsLoopback()
}

func (n NodeAddr) equal(addr NodeAddr) bool {
	return n == addr || (n.port == addr.port && n.IsLoopback() && addr.IsLoopback())
}
