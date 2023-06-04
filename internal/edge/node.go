// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/keystore"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
)

// Config is a structure for configuring
// a KES server API.
type APIConfig struct {
	// Timeout is the duration after which a request
	// times out. If Timeout <= 0 the API default
	// is used.
	Timeout time.Duration

	// InsecureSkipAuth controls whether the API verifies
	// client identities. If InsecureSkipAuth is true,
	// the API accepts requests from arbitrary identities.
	// In this mode, the API can be used by anyone who can
	// communicate to the KES server over HTTPS.
	// This should only be set for testing or in certain
	// cases for APIs that don't expose sensitive information,
	// like metrics.
	InsecureSkipAuth bool
}

type Node struct {
	Admin kes.Identity

	Keys *keystore.Cache

	Policies *PolicyMap

	Metrics *metric.Metrics

	AuditLog *log.Logger

	ErrorLog *log.Logger

	Proxy *auth.TLSProxy

	APIConfig map[string]APIConfig
}
