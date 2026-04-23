// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "log"

// bogoShim is a stub. The full bogo shim test is not supported outside
// the Go standard library tree.
func bogoShim() {
	log.Fatal("bogo shim mode not supported in psiphon-tls")
}
