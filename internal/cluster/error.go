// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"net/http"

	"github.com/minio/kes-go"
)

var ErrNodeClosed = kes.NewError(http.StatusServiceUnavailable, "cluster: node closed")

type VoteError struct {
	StatusCode int
}

func (e VoteError) Error() string { return "" }

type ReplicationError struct {
	StatusCode int
}

func (e ReplicationError) Error() string { return "" }
