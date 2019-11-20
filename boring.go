// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdsa"
	"crypto/internal/boring"
	"crypto/internal/boring/fipstls"
	"crypto/rsa"
	"crypto/x509"
)

// boringEnabled is an alias of boring.Enabled to avoid a new import in common.go.
const boringEnabled = boring.Enabled

// needFIPS returns fipstls.Required(); it avoids a new import in common.go.
func needFIPS() bool {
	return fipstls.Required()
}

// fipsMinVersion replaces c.minVersion in FIPS-only mode.
func fipsMinVersion(c *Config) uint16 {
	// FIPS requires TLS 1.2.
	return VersionTLS12
}

// fipsMaxVersion replaces c.maxVersion in FIPS-only mode.
func fipsMaxVersion(c *Config) uint16 {
	// FIPS requires TLS 1.2.
	return VersionTLS12
}

// default defaultFIPSCurvePreferences is the FIPS-allowed curves,
// in preference order (most preferable first).
var defaultFIPSCurvePreferences = []CurveID{CurveP256, CurveP384, CurveP521}

// fipsCurvePreferences replaces c.curvePreferences in FIPS-only mode.
func fipsCurvePreferences(c *Config) []CurveID {
	if c == nil || len(c.CurvePreferences) == 0 {
		return defaultFIPSCurvePreferences
	}
	var list []CurveID
	for _, id := range c.CurvePreferences {
		for _, allowed := range defaultFIPSCurvePreferences {
			if id == allowed {
				list = append(list, id)
				break
			}
		}
	}
	return list
}

// default FIPSCipherSuites is the FIPS-allowed cipher suites,
// in preference order (most preferable first).
var defaultFIPSCipherSuites = []uint16{
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// fipsCipherSuites replaces c.cipherSuites in FIPS-only mode.
func fipsCipherSuites(c *Config) []uint16 {
	if c == nil || c.CipherSuites == nil {
		return defaultFIPSCipherSuites
	}
	var list []uint16
	for _, id := range c.CipherSuites {
		for _, allowed := range defaultFIPSCipherSuites {
			if id == allowed {
				list = append(list, id)
				break
			}
		}
	}
	return list
}

// isBoringCertificate reports whether a certificate may be used
// when constructing a verified chain.
// It is called for each leaf, intermediate, and root certificate.
func isBoringCertificate(c *x509.Certificate) bool {
	if !needFIPS() {
		// Everything is OK if we haven't forced FIPS-only mode.
		return true
	}

	// Otherwise the key must be RSA 2048, RSA 3072, or ECDSA P-256.
	switch k := c.PublicKey.(type) {
	default:
		return false
	case *rsa.PublicKey:
		if size := k.N.BitLen(); size != 2048 && size != 3072 {
			return false
		}
	case *ecdsa.PublicKey:
		if name := k.Curve.Params().Name; name != "P-256" && name != "P-384" {
			return false
		}
	}

	return true
}

// fipsSupportedSignatureAlgorithms currently are a subset of
// defaultSupportedSignatureAlgorithms without Ed25519 and SHA-1.
var fipsSupportedSignatureAlgorithms = []SignatureScheme{
	PSSWithSHA256,
	PSSWithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA256,
	ECDSAWithP256AndSHA256,
	PKCS1WithSHA384,
	ECDSAWithP384AndSHA384,
	PKCS1WithSHA512,
	ECDSAWithP521AndSHA512,
}

// supportedSignatureAlgorithms returns the supported signature algorithms.
func supportedSignatureAlgorithms() []SignatureScheme {
	if !needFIPS() {
		return defaultSupportedSignatureAlgorithms
	}
	return fipsSupportedSignatureAlgorithms
}

var testingOnlyForceClientHelloSignatureAlgorithms []SignatureScheme
