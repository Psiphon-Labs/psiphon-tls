// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug is a stub replacing crypto/internal/fips140deps/godebug.
// GODEBUG settings are not supported; values always return empty string.
package godebug

type Setting struct {
	name string
}

func New(name string) *Setting {
	return &Setting{name: name}
}

func (s *Setting) Value() string {
	return ""
}

func (s *Setting) IncNonDefault() {
	// no-op: GODEBUG telemetry not supported outside stdlib
}

func Value(name string) string {
	return ""
}
