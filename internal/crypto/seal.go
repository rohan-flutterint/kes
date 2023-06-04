// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/crypto/fips"
)

// ParseSealKey parses a formatted SealKey and returns the
// value it represents.
func ParseSealKey(s string) (*SealKey, error) {
	const (
		Prefix         = "kes:v1:"
		AES256Prefix   = "aes256:"
		ChaCha20Prefix = "chacha20:"
	)

	if !strings.HasPrefix(s, Prefix) {
		return nil, errors.New("crypto: invalid seal key: missing '" + Prefix + "' prefix")
	}
	s = strings.TrimPrefix(s, Prefix)

	var cipher SecretKeyCipher
	switch {
	case strings.HasPrefix(s, AES256Prefix):
		s = strings.TrimPrefix(s, AES256Prefix)
		cipher = AES256
	case strings.HasPrefix(s, ChaCha20Prefix):
		s = strings.TrimPrefix(s, ChaCha20Prefix)
		cipher = ChaCha20
	default:
		return nil, errors.New("crypto: invalid seal key: cipher not supported")
	}

	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("crypto: invalid seal key: invalid key length")
	}

	return &SealKey{
		cipher: cipher,
		key:    key[:32],
	}, nil
}

// GenerateSealKey generates a new random SealKey.
//
// If random is nil the standard library crypto/rand.Reader is used.
func GenerateSealKey(random io.Reader) (*SealKey, error) {
	if random == nil {
		random = rand.Reader
	}

	var cipher SecretKeyCipher
	if fips.Mode > fips.ModeNone || cpu.HasAESGCM() {
		cipher = AES256
	} else {
		cipher = ChaCha20
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(random, key); err != nil {
		return nil, err
	}
	return &SealKey{
		key:    key,
		cipher: cipher,
	}, nil
}

// SealKey represents a seal key used for (un)sealing a cluster root key.
type SealKey struct {
	key    []byte
	cipher SecretKeyCipher
}

// Name returns the sealing provider name.
func (*SealKey) Name() string { return "kes:v1:seal:env" }

// GenerateAPIKey generates an API key from provided seed.
//
// The seed may be nil.
func (e *SealKey) GenerateAPIKey(seed []byte) (kes.APIKey, error) {
	if fips.Mode == fips.ModeStrict {
		return nil, errors.New("crypto: ED25519 API keys not supported by FIPS module")
	}

	random := fips.DeriveKey(sha256.New, e.key, 32, []byte("kes:v1:api_key"), seed)
	return kes.GenerateAPIKey(bytes.NewReader(random))
}

// Seal encrypts and authenticates the plaintext.
func (e *SealKey) Seal(plaintext []byte) ([]byte, error) {
	key, err := NewSecretKey(e.cipher, fips.DeriveKey(sha256.New, e.key, SecretKeySize, []byte("kes:v1:root_key"), nil))
	if err != nil {
		return nil, err
	}
	return key.Encrypt(plaintext, nil)
}

// Unseal decrypts and authenticates the ciphertext.
func (e *SealKey) Unseal(ciphertext []byte) ([]byte, error) {
	key, err := NewSecretKey(e.cipher, fips.DeriveKey(sha256.New, e.key, SecretKeySize, []byte("kes:v1:root_key"), nil))
	if err != nil {
		return nil, err
	}
	return key.Decrypt(ciphertext, nil)
}

// String returns the string representation of the SealKey.
func (e *SealKey) String() string {
	const (
		Prefix         = "kes:v1:"
		AES256Prefix   = "aes256:"
		ChaCha20Prefix = "chacha20:"
	)

	key := base64.StdEncoding.EncodeToString(e.key)
	switch e.cipher {
	case AES256:
		return Prefix + AES256Prefix + key
	case ChaCha20:
		return Prefix + ChaCha20Prefix + key
	default:
		return "%" + strconv.Itoa(int(e.cipher))
	}
}
