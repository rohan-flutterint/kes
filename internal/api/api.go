// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/kes-go"
)

// API describes a KES server API.
type API struct {
	Method  string        // The HTTP method
	Path    string        // The URI API path
	MaxBody int64         // The max. body size the API accepts
	Timeout time.Duration // The duration after which an API request times out. 0 means no timeout
	Verify  bool          // Whether the API verifies the client identity

	// Handler implements the API.
	//
	// When invoked by the API's ServeHTTP method, the handler
	// can rely upon:
	//  - the request method matching the API's HTTP method.
	//  - the API path being a prefix of the request URL.
	//  - the request body being limited to the API's MaxBody size.
	//  - the request timing out after the duration specified for the API.
	Handler http.Handler

	_ [0]int
}

// ServerHTTP takes an HTTP Request and ResponseWriter and executes the
// API's Handler.
func (a API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.Method == http.MethodPut && r.Method == http.MethodPost {
		r.Method = http.MethodPut
	}
	if r.Method != a.Method {
		w.Header().Set("Accept", a.Method)
		Fail(w, kes.NewError(http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed)))
		return
	}
	if !strings.HasPrefix(r.URL.Path, a.Path) {
		Fail(w, fmt.Errorf("api: patch mismatch: received '%s' - expected '%s'", r.URL.Path, a.Path))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, a.MaxBody)

	if a.Timeout > 0 {
		switch err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(a.Timeout)); {
		case errors.Is(err, http.ErrNotSupported):
			Fail(w, errors.New("internal error: HTTP connection does not accept a timeout"))
			return
		case err != nil:
			Fail(w, fmt.Errorf("internal error: %v", err))
			return
		}
	}
	a.Handler.ServeHTTP(w, r)
}

// A HandlerFunc is an adapter that allows the use of
// ordinary functions as HTTP handlers.
//
// In contrast to the http.HandlerFunc type, HandlerFunc
// returns an error in case of a failed operation.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP calls f(w, r). If f returns a non-nil error
// HandlerFunc(f) sends the error to the client by calling
// Fail.
// If f return nil and does not set a custom response code
// then ServeHTTP responds with 200 OK and an empty response
// body.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f(w, r); err != nil {
		Fail(w, err)
		return
	}
}

const (
	maxNameLen   = 128
	maxPrefixLen = 128
)

func trimPath(url *url.URL, path string, f func(string) error) (string, error) {
	s := strings.TrimPrefix(url.Path, path)
	if len(s) == len(url.Path) && path != "" {
		return "", fmt.Errorf("api: invalid path: '%s' is not a prefix of '%s'", path, url.Path)
	}
	if err := f(s); err != nil {
		return "", err
	}
	return s, nil
}

func isValidPrefix(s string) error {
	if len(s) > maxPrefixLen {
		return kes.NewError(http.StatusBadRequest, "prefix is too long")
	}
	for _, r := range s { // Valid characters are: [ 0-9 , A-Z , a-z , - , _ , * ]
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		case r == '_':
		default:
			return kes.NewError(http.StatusBadRequest, "prefix contains invalid character")
		}
	}
	return nil
}

func IsValidName(s string) error {
	return verifyName(s)
}

func IsValidPattern(s string) error {
	return verifyPattern(s)
}

// verifyName reports whether the name is valid.
//
// A valid name must only contain numbers (0-9),
// letters (a-z and A-Z) and '-' as well as '_'
// characters.
func verifyName(name string) error {
	const MaxLength = 80 // Some arbitrary but reasonable limit

	if name == "" {
		return kes.NewError(http.StatusBadRequest, "invalid argument: name is empty")
	}
	if len(name) > MaxLength {
		return kes.NewError(http.StatusBadRequest, "invalid argument: name is too long")
	}
	for _, r := range name { // Valid characters are: [ 0-9 , A-Z , a-z , - , _ ]
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		case r == '_':
		default:
			return kes.NewError(http.StatusBadRequest, "invalid argument: name contains invalid character")
		}
	}
	return nil
}

// verifyPattern reports whether the pattern is valid.
//
// A valid pattern must only contain numbers (0-9),
// letters (a-z and A-Z) and '-', '_' as well as '*'
// characters.
func verifyPattern(pattern string) error {
	const MaxLength = 80 // Some arbitrary but reasonable limit

	if pattern == "" {
		return kes.NewError(http.StatusBadRequest, "invalid argument: pattern is empty")
	}
	if len(pattern) > MaxLength {
		return kes.NewError(http.StatusBadRequest, "invalid argument: pattern is too long")
	}
	for _, r := range pattern { // Valid characters are: [ 0-9 , A-Z , a-z , - , _ , * ]
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		case r == '_':
		case r == '*':
		default:
			return kes.NewError(http.StatusBadRequest, "invalid argument: pattern contains invalid character")
		}
	}
	return nil
}
