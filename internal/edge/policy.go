// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"fmt"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/edge"
	"github.com/minio/kes/internal/auth"
)

func NewPolicyMap(policies map[string]edge.Policy, owner kes.Identity) (*PolicyMap, error) {
	m := &PolicyMap{
		Identity: make(map[kes.Identity]string),
		Policy:   make(map[string]*auth.Policy),
	}

	now := time.Now().UTC()
	for name, def := range policies {
		allow := make(map[string]struct{}, len(def.Allow))
		for _, path := range def.Allow {
			allow[path] = struct{}{}
		}
		deny := make(map[string]struct{}, len(def.Deny))
		for _, path := range def.Deny {
			deny[path] = struct{}{}
		}

		p := &auth.Policy{
			Allow:     allow,
			Deny:      deny,
			CreatedAt: now,
			CreatedBy: owner,
		}
		m.Policy[name] = p

		if len(def.Identities) == 0 {
			continue
		}
		for _, id := range def.Identities {
			if id.IsUnknown() {
				continue
			}
			if v, ok := m.Identity[id]; ok {
				return nil, fmt.Errorf("edge: cannot assign policy '%s' to identity '%s': identity is already assigned to policy '%s'", name, id, v)
			}
			m.Identity[id] = name
		}
	}
	return m, nil
}

type PolicyMap struct {
	Identity map[kes.Identity]string
	Policy   map[string]*auth.Policy
}

func (m *PolicyMap) Lookup(id kes.Identity) (string, *auth.Policy, error) {
	name, ok := m.Identity[id]
	if !ok {
		return "", nil, kes.ErrIdentityNotFound
	}
	policy, ok := m.Policy[name]
	if !ok {
		return "", nil, kes.ErrPolicyNotFound
	}
	return name, policy, nil
}

func (m *PolicyMap) Get(name string) (*auth.Policy, error) {
	if p, ok := m.Policy[name]; ok {
		return p, nil
	}
	return nil, kes.ErrPolicyNotFound
}
