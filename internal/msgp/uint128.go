// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package msgp

//go:generate msgp -io=true

//msgp:tuple Uint128
type Uint128 struct {
	Low, High uint64
}
