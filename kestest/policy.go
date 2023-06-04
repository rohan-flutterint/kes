// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kestest

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	edgeapi "github.com/minio/kes/internal/edge"
)

func NewPolicyMap(admin kes.Identity) *PolicyMap {
	return &PolicyMap{
		admin: admin,
		policies: &edgeapi.PolicyMap{
			Identity: make(map[kes.Identity]string),
			Policy:   make(map[string]*auth.Policy),
		},
	}
}

type PolicyMap struct {
	admin    kes.Identity
	policies *edgeapi.PolicyMap
}

func (m *PolicyMap) Admin() kes.Identity { return m.admin }

func (m *PolicyMap) Add(name string, policy *kes.Policy) {
	allow := make(map[string]struct{}, len(policy.Allow))
	for path := range policy.Allow {
		allow[path] = struct{}{}
	}
	deny := make(map[string]struct{}, len(policy.Deny))
	for path := range policy.Deny {
		deny[path] = struct{}{}
	}

	m.policies.Policy[name] = &auth.Policy{
		Allow:     allow,
		Deny:      deny,
		CreatedAt: time.Now().UTC(),
		CreatedBy: m.admin,
	}
}

func (m *PolicyMap) Allow(name string, paths ...string) {
	allow := make(map[string]kes.Rule, len(paths))
	for _, path := range paths {
		allow[path] = struct{}{}
	}
	m.Add(name, &kes.Policy{
		Allow: allow,
	})
}

func (m *PolicyMap) Assign(name string, ids ...kes.Identity) {
	if _, ok := m.policies.Policy[name]; !ok {
		return
	}
	for _, id := range ids {
		m.policies.Identity[id] = name
	}
}

// Identify returns the Identity of the TLS certificate.
//
// It computes the Identity as fingerprint of the
// X.509 leaf certificate.
func Identify(cert *tls.Certificate) kes.Identity {
	if cert.Leaf == nil {
		var err error
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			panic(fmt.Sprintf("kestest: failed to parse X.509 certificate: %v", err))
		}
	}

	id := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	return kes.Identity(hex.EncodeToString(id[:]))
}
