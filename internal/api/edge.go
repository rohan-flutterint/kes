// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/edge/kv"
	"github.com/minio/kes/internal/audit"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/edge"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/internal/keystore"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/sys"
	"github.com/prometheus/common/expfmt"
)

func NewEdgeRouter(node *edge.Node) *Router {
	mux := http.NewServeMux()

	r := &Router{
		Handler: mux,
	}
	r.APIs = append(r.APIs, edgeVersion(node))
	r.APIs = append(r.APIs, edgeReady(node))
	r.APIs = append(r.APIs, edgeStatus(node))
	r.APIs = append(r.APIs, edgeMetrics(node))
	r.APIs = append(r.APIs, edgeListAPIs(r, node))

	r.APIs = append(r.APIs, edgeCreateKey(node))
	r.APIs = append(r.APIs, edgeImportKey(node))
	r.APIs = append(r.APIs, edgeDescribeKey(node))
	r.APIs = append(r.APIs, edgeDeleteKey(node))
	r.APIs = append(r.APIs, edgeListKeys(node))
	r.APIs = append(r.APIs, edgeGenerateKey(node))
	r.APIs = append(r.APIs, edgeEncryptKey(node))
	r.APIs = append(r.APIs, edgeDecryptKey(node))
	r.APIs = append(r.APIs, edgeBulkDecryptKey(node))

	r.APIs = append(r.APIs, edgeDescribePolicy(node))
	r.APIs = append(r.APIs, edgeReadPolicy(node))
	r.APIs = append(r.APIs, edgeListPolicies(node))

	r.APIs = append(r.APIs, edgeDescribeIdentity(node))
	r.APIs = append(r.APIs, edgeSelfDescribeIdentity(node))
	r.APIs = append(r.APIs, edgeListIdentities(node))

	r.APIs = append(r.APIs, edgeErrorLog(node))
	r.APIs = append(r.APIs, edgeAuditLog(node))

	for _, a := range r.APIs {
		mux.Handle(a.Path, a) // proxy(config.Proxy, a))
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		Fail(w, kes.NewError(http.StatusNotImplemented, "not implemented"))
	}))
	return r
}

// verifyEdgeRequest
func verifyRequest(r *http.Request, admin kes.Identity, policies *edge.PolicyMap) (kes.Identity, error) {
	identity, err := auth.IdentifyRequest(r.TLS)
	if err != nil {
		return identity, err
	}
	if identity == admin {
		return identity, nil
	}

	_, policy, err := policies.Lookup(identity)
	if err != nil {
		return identity, kes.ErrNotAllowed
	}
	return identity, policy.Verify(r)
}

func edgeVersion(node *edge.Node) API {
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

func edgeReady(node *edge.Node) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/ready"
		MaxBody = 0
	)
	var (
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
		Verify = !c.InsecureSkipAuth
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		if Verify {
			if _, err := verifyRequest(r, node.Admin, node.Policies); err != nil {
				return err
			}
		}

		_, err := node.Keys.Status(r.Context())
		if _, ok := kv.IsUnreachable(err); ok {
			return kes.NewError(http.StatusGatewayTimeout, err.Error())
		}
		if err != nil {
			return kes.NewError(http.StatusBadGateway, err.Error())
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Verify:  Verify,
		Timeout: Timeout,
		Handler: handler,
	}
}

func edgeStatus(node *edge.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/status"
		MaxBody     = 0
		ContentType = "application/json"
	)
	var (
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
		Verify = !c.InsecureSkipAuth
	}

	startTime := time.Now().UTC()
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		if Verify {
			if _, err := verifyRequest(r, node.Admin, node.Policies); err != nil {
				return err
			}
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

		state, err := node.Keys.Status(r.Context())
		if err != nil {
			response.KeyStoreUnavailable = true
			_, response.KeyStoreUnreachable = kv.IsUnreachable(err)
		} else {
			latency := state.Latency.Round(time.Millisecond)
			if latency == 0 { // Make sure we actually send a latency even if the key store respond time is < 1ms.
				latency = 1 * time.Millisecond
			}
			response.KeyStoreLatency = latency.Milliseconds()
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
		Verify:  Verify,
		Timeout: Timeout,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeMetrics(node *edge.Node) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/metrics"
		MaxBody = 0
	)
	var (
		Verify  = true
		Timeout = 15 * time.Second
	)
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
		Verify = !c.InsecureSkipAuth
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		if Verify {
			if _, err := verifyRequest(r, node.Admin, node.Policies); err != nil {
				return err
			}
		}

		contentType := expfmt.Negotiate(r.Header)
		w.Header().Set("Content-Type", string(contentType))
		w.WriteHeader(http.StatusOK)

		node.Metrics.EncodeTo(expfmt.NewEncoder(w, contentType))
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

func edgeListAPIs(router *Router, node *edge.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/api"
		MaxBody     = 0
		ContentType = "application/json"
	)
	var (
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
		Verify = !c.InsecureSkipAuth
	}

	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		if Verify {
			if _, err := verifyRequest(r, node.Admin, node.Policies); err != nil {
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
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeCreateKey(node *edge.Node) API {
	const (
		Method        = http.MethodPost
		APIPath       = "/v1/key/create/"
		MaxBody int64 = 0
		Verify        = true
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}

	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		identity, err := verifyRequest(r, node.Admin, node.Policies)
		if err != nil {
			return err
		}

		var cipher crypto.SecretKeyCipher
		if fips.Mode > fips.ModeNone || cpu.HasAESGCM() {
			cipher = kes.AES256
		} else {
			cipher = kes.ChaCha20
		}

		key, err := crypto.GenerateSecretKey(cipher, rand.Reader)
		if err != nil {
			return err
		}
		if err = node.Keys.Create(r.Context(), name, crypto.SecretKeyVersion{
			Key:       key,
			CreatedAt: time.Now(),
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
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeImportKey(node *edge.Node) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/key/import/"
		MaxBody = 1 * mem.MiB
		Verify  = true
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}

	type Request struct {
		Bytes     []byte           `json:"bytes"`
		Algorithm kes.KeyAlgorithm `json:"algorithm"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		identity, err := verifyRequest(r, node.Admin, node.Policies)
		if err != nil {
			return err
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}

		var cipher crypto.SecretKeyCipher
		switch req.Algorithm {
		case kes.AES256:
			cipher = crypto.AES256
		case kes.ChaCha20:
			cipher = crypto.ChaCha20
		default:
			return kes.NewError(http.StatusBadRequest, "algorithm not supported")
		}

		key, err := crypto.NewSecretKey(cipher, req.Bytes)
		if err != nil {
			return err
		}
		if err = node.Keys.Create(r.Context(), name, crypto.SecretKeyVersion{
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
		MaxBody: int64(MaxBody),
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeDescribeKey(node *edge.Node) API {
	var (
		Method  = http.MethodGet
		APIPath = "/v1/key/describe/"
		MaxBody int64
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		key, err := node.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Length", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DescribeKeyResponse{
			Version:   0,
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
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeDeleteKey(node *edge.Node) API {
	var (
		Method  = http.MethodDelete
		APIPath = "/v1/key/delete/"
		MaxBody int64
		Verify  = true
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		if err := node.Keys.Delete(r.Context(), name); err != nil {
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
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeGenerateKey(node *edge.Node) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/generate/"
		MaxBody     = 1 * mem.MiB
		Verify      = true
		ContentType = "application/json"
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}

	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		var req GenerateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		key, err := node.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}
		dataKey := make([]byte, 32)
		if _, err = rand.Read(dataKey); err != nil {
			return err
		}
		ciphertext, err := key.Key.Encrypt(dataKey, req.Context)
		if err != nil {
			return err
		}

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
		MaxBody: int64(MaxBody),
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeEncryptKey(node *edge.Node) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/encrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Verify      = true
		ContentType = "application/json"
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		var req EncryptKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}

		key, err := node.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}
		ciphertext, err := key.Key.Encrypt(req.Plaintext, req.Context)
		if err != nil {
			return err
		}

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
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeDecryptKey(node *edge.Node) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Verify      = true
		ContentType = "application/json"
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		var req DecryptKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return err
		}
		key, err := node.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}
		ciphertext, err := keystore.DecodeCiphertext(req.Ciphertext)
		if err != nil {
			return err
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
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeBulkDecryptKey(node *edge.Node) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/bulk/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Verify      = true
		ContentType = "application/json"
		MaxRequests = 1000 // For now, we limit the number of decryption requests in a single API call to 1000.
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		key, err := node.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}
		var (
			requests  []DecryptKeyRequest
			responses []DecryptKeyResponse
		)
		if err = json.NewDecoder(r.Body).Decode(&requests); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		if len(requests) > MaxRequests {
			return kes.NewError(http.StatusBadRequest, "too many ciphertexts")
		}
		responses = make([]DecryptKeyResponse, 0, len(requests))
		for _, req := range requests {
			ciphertext, err := keystore.DecodeCiphertext(req.Ciphertext)
			if err != nil {
				return err
			}
			plaintext, err := key.Key.Decrypt(ciphertext, req.Context)
			if err != nil {
				return err
			}
			responses = append(responses, DecryptKeyResponse{
				Plaintext: plaintext,
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
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeListKeys(node *edge.Node) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/key/list/"
		MaxBody     int64
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		prefix, err := trimPath(r.URL, APIPath, isValidPrefix)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		names, prefix, err := node.Keys.List(r.Context(), prefix, -1)
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
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeDescribePolicy(node *edge.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/describe/"
		MaxBody     = 0
		Verify      = true
		ContentType = "application/json"
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		policy, err := node.Policies.Get(name)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DescribePolicyResponse{
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeReadPolicy(node *edge.Node) API {
	const (
		Method            = http.MethodGet
		APIPath           = "/v1/policy/read/"
		MaxBody     int64 = 0
		Verify            = true
		ContentType       = "application/json"
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		policy, err := node.Policies.Get(name)
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

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ReadPolicyResponse{
			Allow:     allow,
			Deny:      deny,
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeListPolicies(node *edge.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/list/"
		MaxBody     = 0
		Verify      = true
		ContentType = "application/json"
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		prefix, err := trimPath(r.URL, APIPath, isValidPrefix)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}
		names := make([]string, 0, len(node.Policies.Policy))
		for name := range node.Policies.Policy {
			if strings.HasPrefix(name, prefix) {
				names = append(names, name)
			}
		}
		sort.Strings(names)

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(ListPoliciesResponse{Names: names})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeDescribeIdentity(node *edge.Node) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/describe/"
		MaxBody     int64
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := trimPath(r.URL, APIPath, IsValidName)
		if err != nil {
			return err
		}
		if _, err := verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		var policyName string
		if id := kes.Identity(name); id != node.Admin {
			name, _, err := node.Policies.Lookup(kes.Identity(name))
			if err != nil {
				return err
			}
			policyName = name
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DescribeIdentityResponse{
			Policy:  policyName,
			IsAdmin: node.Admin == kes.Identity(name),
			// TODO:			// CreatedAt: time.Time{},
			CreatedBy: node.Admin,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeSelfDescribeIdentity(node *edge.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/self/describe"
		MaxBody     = 0
		Verify      = false
		ContentType = "application/json"
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity, err := auth.IdentifyRequest(r.TLS)
		if err != nil {
			return err
		}

		var (
			name   string
			policy *auth.Policy
		)
		if identity != node.Admin {
			name, policy, err = node.Policies.Lookup(identity)
			if err != nil {
				return err
			}
		}

		resp := SelfDescribeIdentityResponse{
			Identity:  identity,
			IsAdmin:   identity == node.Admin,
			Policy:    name,
			CreatedBy: node.Admin,
		}
		if policy != nil {
			resp.Allow = policy.Allow
			resp.Deny = policy.Deny
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeListIdentities(node *edge.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/list/"
		MaxBody     = 0
		Verify      = true
		ContentType = "application/json"
	)
	Timeout := 15 * time.Second
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		prefix, err := trimPath(r.URL, APIPath, isValidPrefix)
		if err != nil {
			return err
		}
		if _, err = verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		identities := make([]kes.Identity, 0, len(node.Policies.Policy))
		for id := range node.Policies.Identity {
			if strings.HasPrefix(id.String(), prefix) {
				identities = append(identities, id)
			}
		}
		sort.Slice(identities, func(i, j int) bool { return identities[i] < identities[j] })

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(ListIdentitiesResponse{Identities: identities})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(audit.Log(node.AuditLog, handler))),
	}
}

func edgeErrorLog(node *edge.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/log/error"
		MaxBody     = 0
		Verify      = true
		ContentType = "application/x-ndjson"
	)
	Timeout := 0 * time.Second // No timeout
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		if _, err := verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)

		out := log.NewErrEncoder(https.FlushOnWrite(w))
		node.ErrorLog.Add(out)
		defer node.ErrorLog.Remove(out)

		<-r.Context().Done() // Wait for the client to close the connection
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(handler)),
	}
}

func edgeAuditLog(node *edge.Node) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/log/audit"
		MaxBody     = 0
		Verify      = true
		ContentType = "application/x-ndjson"
	)
	Timeout := 0 * time.Second // No timeout
	if c, ok := node.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		if _, err := verifyRequest(r, node.Admin, node.Policies); err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)

		out := https.FlushOnWrite(w)
		node.AuditLog.Add(out)
		defer node.AuditLog.Remove(out)

		<-r.Context().Done() // Wait for the client to close the connection
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: node.Metrics.Count(node.Metrics.Latency(handler)),
	}
}
