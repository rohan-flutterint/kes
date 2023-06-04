// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package crypto_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"

	"github.com/minio/kes/internal/crypto"
)

func ExampleSealKey_GenerateAPIKey() {
	const SealKey = "kes:v1:aes256:xVPTWGcEMj7PRIWJ8Hr8uxmdf/NUrCyXthNeSvU9t+o="

	key, err := crypto.ParseSealKey(SealKey)
	if err != nil {
		log.Fatalf("failed to parse seal key: %v", err)
	}

	apiKey, err := key.GenerateAPIKey(nil)
	if err != nil {
		log.Fatalf("failed to generate API key: %v", err)
	}

	fmt.Println(apiKey.String())
	fmt.Println(apiKey.Identity())

	// Output:
	// kes:v1:ABCpPQFHycJp0TEBEalMHsyrkE/FTHHk4Jqsl7Az7MlF
	// 144353570a5ec16b42c8b4e446bb98dce0bc0a84c0996084da878f4e6379b582
}

func ExampleSealKey_Seal() {
	const SealKey = "kes:v1:aes256:xVPTWGcEMj7PRIWJ8Hr8uxmdf/NUrCyXthNeSvU9t+o="

	key, err := crypto.ParseSealKey(SealKey)
	if err != nil {
		log.Fatalf("failed to parse seal key: %v", err)
	}

	rootKey := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, rootKey); err != nil {
		log.Fatalf("failed to generate random root key")
	}

	ciphertext, err := key.Seal(rootKey)
	if err != nil {
		log.Fatalf("failed to seal root key")
	}
	_ = ciphertext

	// Output:
}

func ExampleSealKey_Unseal() {
	const (
		SealKey    = "kes:v1:aes256:xVPTWGcEMj7PRIWJ8Hr8uxmdf/NUrCyXthNeSvU9t+o="
		Ciphertext = "eFWaMJigBE2I6prRx6GM0y0rJompMaRKCur07Be5QqHdA7L63O1+iYva4TH7vDDqzyIWzrfNKA/zV/36njkShGswYSZPqsnzIkimbw=="
	)

	key, err := crypto.ParseSealKey(SealKey)
	if err != nil {
		log.Fatalf("failed to parse seal key: %v", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(Ciphertext)
	if err != nil {
		log.Fatalf("failed to decode ciphertext: %v", err)
	}

	plaintext, err := key.Unseal(ciphertext)
	if err != nil {
		log.Fatalf("failed to unseal root key: %v", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(plaintext))

	// Output:
	// njCb7P3TSy6iXkgXZY4007pwxWWar1WWd5/lUN1LTpE=
}

func ExampleSecretKey_Encrypt() {
	key, err := crypto.GenerateSecretKey(crypto.AES256, nil)
	if err != nil {
		log.Fatalf("failed to generate AES256 key: %v", err)
	}

	ciphertext, err := key.Encrypt([]byte("Hello World"), nil)
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}
	_ = ciphertext
	// Output:
}

func ExampleSecretKey_Decrypt() {
	const (
		KeyBytes        = "8612a2d23764284e0da438de559a3d8162983ab574ec69f95c1aeed6a4e1077d"
		CiphertextBytes = "6a3912cfee99ca51c12004f8fb3ea912b45966f3e5e33cd886993084f9d2c1433028a59231e26f9ec0c1cd2426a97d4cc9988ba968b9b0"
	)

	keyBytes, _ := hex.DecodeString(KeyBytes)
	ciphertext, _ := hex.DecodeString(CiphertextBytes)

	key, err := crypto.NewSecretKey(crypto.AES256, keyBytes)
	if err != nil {
		log.Fatalf("failed to create AES256 key: %v", err)
	}

	plaintext, err := key.Decrypt(ciphertext, nil)
	if err != nil {
		log.Fatalf("failed to decrypt ciphertext: %v", err)
	}
	fmt.Println(string(plaintext))

	// Output:
	// Hello World
}
