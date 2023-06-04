// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cluster"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/msgp"
	"github.com/minio/kes/internal/sys"
	"github.com/prometheus/common/expfmt"
	bolt "go.etcd.io/bbolt"
)

func NewRouter(node *cluster.Node) *Router {
	mux := http.NewServeMux()
	r := &Router{
		Handler: mux,
	}

	r.APIs = append(r.APIs, version())
	r.APIs = append(r.APIs, status(node))
	r.APIs = append(r.APIs, metrics(node))
	r.APIs = append(r.APIs, listAPI(node, r))

	r.APIs = append(r.APIs, createKey(node))
	r.APIs = append(r.APIs, describeKey(node))
	r.APIs = append(r.APIs, listKeys(node))
	r.APIs = append(r.APIs, deleteKey(node))
	r.APIs = append(r.APIs, encryptKey(node))
	r.APIs = append(r.APIs, generateKey(node))
	r.APIs = append(r.APIs, decryptKey(node))

	r.APIs = append(r.APIs, createSecret(node))
	r.APIs = append(r.APIs, describeSecret(node))
	r.APIs = append(r.APIs, readSecret(node))
	r.APIs = append(r.APIs, deleteSecret(node))
	r.APIs = append(r.APIs, listSecret(node))

	r.APIs = append(r.APIs, assignPolicy(node))
	r.APIs = append(r.APIs, createPolicy(node))
	r.APIs = append(r.APIs, describePolicy(node))
	r.APIs = append(r.APIs, readPolicy(node))
	r.APIs = append(r.APIs, deletePolicy(node))
	r.APIs = append(r.APIs, listPolicies(node))

	r.APIs = append(r.APIs, createIdentity(node))
	r.APIs = append(r.APIs, describeIdentity(node))
	r.APIs = append(r.APIs, selfDescribeIdentity(node))
	r.APIs = append(r.APIs, listIdentity(node))
	r.APIs = append(r.APIs, deleteIdentity(node))

	r.APIs = append(r.APIs, createEnclave(node))
	r.APIs = append(r.APIs, describeEnclave(node))
	r.APIs = append(r.APIs, listEnclaves(node))
	r.APIs = append(r.APIs, deleteEnclave(node))

	r.APIs = append(r.APIs, errorLog(node))
	r.APIs = append(r.APIs, auditLog(node))

	r.APIs = append(r.APIs, replicateClusterEvent(node))
	r.APIs = append(r.APIs, voteForClusterLeader(node))
	r.APIs = append(r.APIs, forwardClusterEvent(node))

	r.APIs = append(r.APIs, expandCluster(node))
	r.APIs = append(r.APIs, describeCluster(node))
	r.APIs = append(r.APIs, shrinkCluster(node))
	r.APIs = append(r.APIs, backupClusterSnapshot(node))
	r.APIs = append(r.APIs, restoreClusterSnapshot(node))

	for _, a := range r.APIs {
		// mux.Handle(a.Path, proxy(config.Proxy, a))
		mux.Handle(a.Path, a)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		Fail(w, kes.NewError(http.StatusNotImplemented, "not implemented"))
	}))
	return r
}

func readEnclaveHeader(h http.Header) (string, error) {
	const EnclaveHeaderKey = "Kes-Enclave"

	v := h.Values(EnclaveHeaderKey)
	if len(v) == 0 {
		return "", kes.ErrEnclaveNotFound
	}

	enclave := v[0]
	if err := IsValidName(enclave); err != nil {
		return "", kes.NewError(http.StatusBadRequest, fmt.Sprintf("invalid enclave name '%s': %v", enclave, err))
	}
	return enclave, nil
}

func version() API {
	const (
		Method      = http.MethodGet
		APIPath     = "/version"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = false
		ContentType = "application/json"
	)
	resp, _ := json.Marshal(VersionRespose{
		Version: sys.BinaryInfo().Version,
		Commit:  sys.BinaryInfo().CommitID,
	})
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
	}
}

func metrics(node *cluster.Node) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/metrics"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		if _, _, err := node.VerifyRequest(r); err != nil {
			return err
		}

		contentType := expfmt.Negotiate(r.Header)
		w.Header().Set("Content-Type", string(contentType))
		w.WriteHeader(http.StatusOK)

		node.Metrics().EncodeTo(expfmt.NewEncoder(w, contentType))
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
	}
}

func status(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/status"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	startTime := time.Now().UTC()
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		if _, _, err := node.VerifyRequest(r); err != nil {
			return err
		}

		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		response := StatusResponse{
			Version: sys.BinaryInfo().Version,
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			UpTime:  time.Since(startTime).Round(time.Second),

			CPUs:       runtime.NumCPU(),
			UsableCPUs: runtime.GOMAXPROCS(0),
			HeapAlloc:  memStats.HeapAlloc,
			StackAlloc: memStats.StackSys,
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func listAPI(node *cluster.Node, router *Router) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/api"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			if _, _, err = node.VerifyRequest(r); err != nil {
				return err
			}
		}

		responses := make([]ListAPIsResponse, 0, len(router.APIs))
		for _, a := range router.APIs {
			responses = append(responses, ListAPIsResponse{
				Method:  a.Method,
				Path:    a.Path,
				MaxBody: a.MaxBody,
				Timeout: int64(a.Timeout.Truncate(time.Second).Seconds()),
				Verify:  a.Verify,
			})
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responses)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func createEnclave(node *cluster.Node) API {
	const (
		Method  = http.MethodPut
		APIPath = "/v1/enclave/create/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			return kes.ErrNotAllowed
		}

		key, err := crypto.GenerateSecretKey(crypto.AES256, rand.Reader)
		if err != nil {
			return err
		}
		if err = node.Apply(r.Context(), &cluster.CreateEnclaveEvent{
			Name:      name,
			Key:       key,
			CreatedAt: time.Now().UTC(),
			CreatedBy: identity,
		}); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
	}
}

func describeEnclave(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/enclave/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return Fail(w, err)
		}
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			return kes.ErrNotAllowed
		}

		enclave, err := node.GetEnclave(r.Context(), name)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(&DescribeEnclaveResponse{
			CreatedAt: enclave.CreatedAt,
			CreatedBy: enclave.CreatedBy,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func listEnclaves(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/enclave/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		prefix, err := trimPath(r.URL, APIPath, isValidPrefix)
		if err != nil {
			return Fail(w, err)
		}
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			return kes.ErrNotAllowed
		}

		var enclaves []string
		enclaves, prefix, err = node.ListEnclaves(r.Context(), prefix)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ListEnclavesResponse{
			Names:      enclaves,
			ContinueAt: prefix,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func deleteEnclave(node *cluster.Node) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/enclave/delete/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			return kes.ErrNotAllowed
		}
		return node.Apply(r.Context(), &cluster.DeleteEnclaveEvent{Name: name})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func createKey(node *cluster.Node) API {
	const (
		Method  = http.MethodPut
		APIPath = "/v1/key/create/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, identity, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		keyBytes := make([]byte, crypto.SecretKeySize)
		if _, err := rand.Read(keyBytes); err != nil {
			return err
		}

		cipher := crypto.AES256
		if fips.Mode == fips.ModeNone && !cpu.HasAESGCM() {
			cipher = crypto.ChaCha20
		}
		key, err := crypto.NewSecretKey(cipher, keyBytes)
		if err != nil {
			return err
		}

		if err = node.Apply(r.Context(), &cluster.CreateSecretKeyRingEvent{
			Enclave:   enclave,
			Name:      name,
			Key:       key,
			CreatedAt: time.Now().UTC(),
			CreatedBy: identity,
		}); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
		Handler: handler,
	}
}

func describeKey(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/key/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		ring, err := node.GetSecretKeyRing(r.Context(), enclave, name)
		if err != nil {
			return err
		}
		key, version := ring.Latest()

		json.NewEncoder(w).Encode(DescribeKeyResponse{
			Name:      name,
			Version:   version,
			CreatedAt: key.CreatedAt,
			CreatedBy: key.CreatedBy,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func deleteKey(node *cluster.Node) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/key/delete/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		if err = node.Apply(r.Context(), &cluster.DeleteSecretKeyRing{
			Enclave: enclave,
			Name:    name,
		}); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func generateKey(node *cluster.Node) API {
	const (
		Method      = http.MethodPut
		APIPath     = "/v1/key/generate/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var req GenerateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}

		ring, err := node.GetSecretKeyRing(r.Context(), enclave, name)
		if err != nil {
			return err
		}
		key, version := ring.Latest()

		dataKey := make([]byte, 32)
		if _, err = rand.Read(dataKey); err != nil {
			return err
		}
		ciphertext, err := key.Key.Encrypt(dataKey, req.Context)
		if err != nil {
			return err
		}
		ciphertext = binary.LittleEndian.AppendUint32(ciphertext, version)

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(GenerateKeyResponse{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func encryptKey(node *cluster.Node) API {
	const (
		Method      = http.MethodPut
		APIPath     = "/v1/key/encrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var req EncryptKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}

		ring, err := node.GetSecretKeyRing(r.Context(), enclave, name)
		if err != nil {
			return err
		}
		key, version := ring.Latest()

		ciphertext, err := key.Key.Encrypt(req.Plaintext, req.Context)
		if err != nil {
			return err
		}
		ciphertext = binary.LittleEndian.AppendUint32(ciphertext, version)

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EncryptKeyResponse{
			Ciphertext: ciphertext,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func decryptKey(node *cluster.Node) API {
	const (
		Method      = http.MethodPut
		APIPath     = "/v1/key/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var req DecryptKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}

		if len(req.Ciphertext) < 4 {
			return kes.ErrDecrypt
		}
		n := len(req.Ciphertext)
		version := binary.LittleEndian.Uint32(req.Ciphertext[n-4:])
		ciphertext := req.Ciphertext[: n-4 : n-4]

		ring, err := node.GetSecretKeyRing(r.Context(), enclave, name)
		if err != nil {
			return err
		}
		key, ok := ring.Get(version)
		if !ok {
			return kes.ErrKeyNotFound
		}

		plaintext, err := key.Key.Decrypt(ciphertext, req.Context)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DecryptKeyResponse{
			Plaintext: plaintext,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func bulkDecryptKey(node *cluster.Node) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/bulk/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
		MaxRequests = 1000 // For now, we limit the number of decryption requests in a single API call to 1000.
	)
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error { return nil }
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func listKeys(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/key/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		prefix, err := trimPath(r.URL, APIPath, isValidPrefix)
		if err != nil {
			return Fail(w, err)
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var names []string
		names, prefix, err = node.ListSecretKeyRings(r.Context(), enclave, prefix)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ListKeysResponse{
			Names:      names,
			ContinueAt: prefix,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func createPolicy(node *cluster.Node) API {
	const (
		Method      = http.MethodPut
		APIPath     = "/v1/policy/create/"
		MaxBody     = int64(1 * mem.MB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, identity, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var req CreatePolicyRequest
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			return err
		}

		return node.Apply(r.Context(), &cluster.CreatePolicyEvent{
			Enclave:   enclave,
			Name:      name,
			Allow:     req.Allow,
			Deny:      req.Deny,
			CreatedAt: time.Now().UTC(),
			CreatedBy: identity,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func assignPolicy(node *cluster.Node) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/policy/assign/"
		MaxBody = int64(1 * mem.KiB)
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error { return nil }
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func describePolicy(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		policy, err := node.GetPolicy(r.Context(), enclave, name)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(DescribePolicyResponse{
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func readPolicy(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/read/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		policy, err := node.GetPolicy(r.Context(), enclave, name)
		if err != nil {
			return err
		}

		allow := make(map[string]struct{}, len(policy.Allow))
		for path := range policy.Allow {
			allow[path] = struct{}{}
		}
		deny := make(map[string]struct{}, len(policy.Deny))
		for path := range policy.Deny {
			deny[path] = struct{}{}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(ReadPolicyResponse{
			Allow:     allow,
			Deny:      deny,
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func deletePolicy(node *cluster.Node) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/policy/delete/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}
		return node.Apply(r.Context(), &cluster.DeletePolicyEvent{
			Enclave: enclave,
			Name:    name,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func listPolicies(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		prefix, err := trimPath(r.URL, APIPath, isValidPrefix)
		if err != nil {
			return Fail(w, err)
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var names []string
		names, prefix, err = node.ListPolicies(r.Context(), enclave, prefix)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ListPoliciesResponse{
			Names:      names,
			ContinueAt: prefix,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func createIdentity(node *cluster.Node) API {
	const (
		Method      = http.MethodPut
		APIPath     = "/v1/identity/create/"
		MaxBody     = int64(1 * mem.MB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, identity, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var req CreateIdentityRequest
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			return err
		}

		var (
			now       = time.Now().UTC()
			ttl       time.Duration
			expiresAt time.Time
		)
		if req.TTL != "" {
			ttl, err = time.ParseDuration(req.TTL)
			if err != nil {
				return err
			}
			if ttl > 0 {
				expiresAt = now.Add(ttl)
			}
		}
		return node.Apply(r.Context(), &cluster.CreateIdentityEvent{
			Enclave:   enclave,
			Identity:  kes.Identity(name),
			Policy:    req.Policy,
			IsAdmin:   req.IsAdmin,
			TTL:       ttl,
			ExpiresAt: expiresAt,
			CreatedAt: now,
			CreatedBy: identity,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func describeIdentity(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		identity, err := node.GetIdentity(r.Context(), enclave, kes.Identity(name))
		if err != nil {
			return err
		}
		var ttl string
		if identity.TTL > 0 {
			ttl = identity.TTL.String()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(DescribeIdentityResponse{
			Policy:    identity.Policy,
			IsAdmin:   identity.IsAdmin,
			Children:  identity.Children.Slice(),
			TTL:       ttl,
			ExpiresAt: identity.ExpiresAt.UTC(),
			CreatedAt: identity.CreatedAt.UTC(),
			CreatedBy: identity.CreatedBy,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func selfDescribeIdentity(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/self/describe"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = false
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		enclave, err := readEnclaveHeader(r.Header)
		if err != nil {
			return err
		}
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if node.IsAdmin(identity) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			return json.NewEncoder(w).Encode(SelfDescribeIdentityResponse{
				Identity: identity,
			})
		}

		self, err := node.GetIdentity(r.Context(), enclave, identity)
		if err != nil {
			return err
		}

		var allow, deny map[string]auth.Rule
		if self.Policy != "" {
			policy, err := node.GetPolicy(r.Context(), enclave, self.Policy)
			if err != nil {
				return err
			}
			allow = policy.Allow
			deny = policy.Deny
		}
		var ttl string
		if self.TTL > 0 {
			ttl = self.TTL.String()
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(SelfDescribeIdentityResponse{
			Identity:  self.Identity,
			IsAdmin:   self.IsAdmin,
			Children:  self.Children.Slice(),
			TTL:       ttl,
			ExpiresAt: self.ExpiresAt.UTC(),
			CreatedAt: self.CreatedAt.UTC(),
			CreatedBy: self.CreatedBy,
			Policy:    self.Policy,
			Allow:     allow,
			Deny:      deny,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func deleteIdentity(node *cluster.Node) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/identity/delete/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		if err = node.Apply(r.Context(), &cluster.DeleteIdentityEvent{
			Enclave:  enclave,
			Identity: kes.Identity(name),
		}); err != nil {
			return err
		}

		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func listIdentity(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		prefix, err := trimPath(r.URL, APIPath, isValidPrefix)
		if err != nil {
			return Fail(w, err)
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var identities []kes.Identity
		identities, prefix, err = node.ListIdentities(r.Context(), enclave, prefix)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ListIdentitiesResponse{
			Identities: identities,
			ContinueAt: prefix,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func errorLog(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/log/error"
		MaxBody     = 0
		Timeout     = 0 * time.Second // No timeout
		Verify      = true
		ContentType = "application/x-ndjson"
	)

	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(handler)),
	}
}

func auditLog(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/log/audit"
		MaxBody     = 0
		Timeout     = 0 * time.Second // No timeout
		Verify      = true
		ContentType = "application/x-ndjson"
	)

	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(handler)),
	}
}

func createSecret(node *cluster.Node) API {
	const (
		Method  = http.MethodPut
		APIPath = "/v1/secret/create/"
		MaxBody = int64(1 * mem.MiB)
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, identity, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		var req CreateSecretRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return err
		}
		if err := node.Apply(r.Context(), &cluster.CreateSecretEvent{
			Enclave:    enclave,
			Name:       name,
			Secret:     req.Secret,
			SecretType: crypto.SecretTypeGeneric,
			CreatedAt:  time.Now().UTC(),
			CreatedBy:  identity,
		}); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func describeSecret(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/secret/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		secret, err := node.GetSecret(r.Context(), enclave, name)
		if err != nil {
			return err
		}
		sec, version := secret.Latest()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DescribeSecretResponse{
			Version:   version,
			CreatedAt: sec.CreatedAt,
			CreatedBy: sec.CreatedBy,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func readSecret(node *cluster.Node) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/secret/read/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		secret, err := node.GetSecret(r.Context(), enclave, name)
		if err != nil {
			return err
		}
		sec, version := secret.Latest()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ReadSecretResponse{
			Version:   version,
			Value:     sec.Value,
			CreatedAt: sec.CreatedAt,
			CreatedBy: sec.CreatedBy,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func deleteSecret(node *cluster.Node) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/secret/delete/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		enclave, _, err := node.VerifyRequest(r)
		if err != nil {
			return err
		}

		if err := node.Apply(r.Context(), &cluster.DeleteSecretEvent{
			Enclave: enclave,
			Name:    name,
		}); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func listSecret(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/secret/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error { return nil }
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
		// Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func expandCluster(node *cluster.Node) API {
	const (
		Method  = http.MethodPut
		APIPath = "/v1/cluster/expand"
		MaxBody = int64(1 * mem.MB)
		Timeout = 15 * time.Second
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			return kes.ErrNotAllowed
		}

		var req ExpandClusterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		member, err := cluster.ParseNodeAddr(req.NodeAddr)
		if err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}

		pr, pw := io.Pipe()
		defer pw.Close()
		defer pr.Close()

		if err := node.DB().View(func(tx *bolt.Tx) error {
			const (
				Scheme  = "https://"
				APIPath = "/v1/cluster/restore"
			)

			url, err := url.JoinPath(Scheme+member.String(), APIPath)
			if err != nil {
				return err
			}
			wReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, url, pr)
			if err != nil {
				return err
			}
			wReq.Header.Set("Content-Length", strconv.FormatInt(tx.Size(), 10))

			go func() {
				_, err := tx.WriteTo(pw)
				pw.CloseWithError(err)
			}()
			resp, err := node.RPC().Client.Do(wReq)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return errors.New(resp.Status)
			}
			return nil
		}); err != nil {
			return err
		}

		members := node.MemberSet()
		if _, ok := members.Add(member); !ok {
			return kes.NewError(http.StatusConflict, "node is already part of the cluster")
		}
		if err := node.Apply(r.Context(), &cluster.ChangeMembersEvent{
			Members: members,
		}); err != nil {
			return err
		}

		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: handler,
	}
}

func describeCluster(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/cluster/describe"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			return kes.ErrNotAllowed
		}

		nodes := make(map[uint64]string)
		for id, addr := range node.MemberSet() {
			nodes[uint64(id)] = addr.String()
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DescribeClusterResponse{
			Nodes:  nodes,
			Leader: uint64(node.Leader()),
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: handler,
	}
}

func shrinkCluster(node *cluster.Node) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/cluster/shrink"
		MaxBody = int64(1 * mem.MB)
		Timeout = 15 * time.Second
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			return kes.ErrNotAllowed
		}

		var req ShrinkClusterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return err
		}
		addr, err := cluster.ParseNodeAddr(req.NodeAddr)
		if err != nil {
			return err
		}

		members := node.MemberSet()
		if _, ok := members.Remove(addr); !ok {
			return errors.New("node is not part of the cluster")
		}
		if err = node.Apply(r.Context(), &cluster.ChangeMembersEvent{
			Members: members,
		}); err != nil {
			return err
		}

		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: handler,
	}
}

func backupClusterSnapshot(node *cluster.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/cluster/backup"
		MaxBody     = 0
		Timeout     = 300 * time.Second
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) {
			return kes.ErrNotAllowed
		}

		return node.DB().View(func(tx *bolt.Tx) error {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.FormatInt(tx.Size(), 10))
			w.WriteHeader(http.StatusOK)

			_, err := tx.WriteTo(w)
			return err
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: handler,
	}
}

func restoreClusterSnapshot(node *cluster.Node) API {
	const (
		Method  = http.MethodPut
		APIPath = "/v1/cluster/restore"
		MaxBody = int64(5 * mem.GB)
		Timeout = 300 * time.Second
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsAdmin(identity) && !node.IsPeer(identity) {
			return kes.ErrNotAllowed
		}

		dbPath := node.DB().Path()
		tmp, err := os.OpenFile(dbPath+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_SYNC, 0o644)
		if err != nil {
			return err
		}
		defer tmp.Close()

		if _, err = io.Copy(tmp, r.Body); err != nil {
			return err
		}
		if err = tmp.Sync(); err != nil {
			return err
		}
		if err = tmp.Close(); err != nil {
			return err
		}

		if err := node.Stop(); err != nil {
			return err
		}
		if err := os.Rename(dbPath+".tmp", dbPath); err != nil {
			node.Restart() // TODO log restart failure
			return err
		}
		if err := node.Restart(); err != nil {
			return err
		}

		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: handler,
	}
}

func replicateClusterEvent(node *cluster.Node) API {
	const (
		Method  = http.MethodPut
		APIPath = "/v1/cluster/rpc/replicate"
		MaxBody = int64(1 * mem.MB)
		Timeout = 15 * time.Second
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsPeer(identity) {
			return kes.ErrNotAllowed
		}
		var req cluster.ReplicationRequest
		if err := msgp.Decode[msgp.ReplicationRequest](r.Body, &req); err != nil {
			return err
		}

		if err := node.Receive(req); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: handler,
	}
}

func voteForClusterLeader(node *cluster.Node) API {
	const (
		Method      = http.MethodPut
		APIPath     = "/v1/cluster/rpc/vote"
		MaxBody     = int64(1 * mem.MB)
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsPeer(identity) {
			return kes.ErrNotAllowed
		}
		var req cluster.VoteRequest
		if err := msgp.Decode[msgp.VoteRequest](r.Body, &req); err != nil {
			return err
		}

		if err := node.Vote(req); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: handler,
	}
}

func forwardClusterEvent(node *cluster.Node) API {
	const (
		Method  = http.MethodPut
		APIPath = "/v1/cluster/rpc/forward"
		MaxBody = int64(1 * mem.MB)
		Timeout = 15 * time.Second
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}
		if !node.IsPeer(identity) {
			return kes.ErrNotAllowed
		}
		var req cluster.ForwardRequest
		if err := msgp.Decode[msgp.ForwardRequest](r.Body, &req); err != nil {
			return err
		}

		event, err := cluster.DecodeEvent(req.EventType, req.Event)
		if err != nil {
			return err
		}
		return node.Apply(r.Context(), event)
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: handler,
	}
}
