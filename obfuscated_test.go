/*
 * Copyright (c) 2016, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// [Psiphon]
// TestObfuscatedSessionTicket exercises the Obfuscated Session Tickets facility.
func TestObfuscatedSessionTicket(t *testing.T) {

	helloIDs := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
	}

	for _, helloID := range helloIDs {
		t.Run(helloID.Str(), func(t *testing.T) {
			runObfuscatedSessionTicket(t, helloID)
		})
	}
}

func runObfuscatedSessionTicket(t *testing.T, helloID utls.ClientHelloID) {

	var standardSessionTicketKey [32]byte
	rand.Read(standardSessionTicketKey[:])

	var obfuscatedSessionTicketSharedSecret [32]byte
	rand.Read(obfuscatedSessionTicketSharedSecret[:])

	// Note: SNI and certificate CN intentionally don't match; if the
	// session ticket is ignored, the TLS handshake will fail with
	// a certificate error.
	clientConfig := &utls.Config{
		ServerName: "www.example.com",
	}

	certificate, err := generateCertificate()
	if err != nil {
		t.Fatalf("generateCertificate failed: %s", err)
	}

	serverConfig := &Config{
		Certificates:     []Certificate{*certificate},
		NextProtos:       []string{"http/1.1"},
		MinVersion:       VersionTLS10,
		SessionTicketKey: obfuscatedSessionTicketSharedSecret,
	}

	serverConfig.SetSessionTicketKeys([][32]byte{
		standardSessionTicketKey, obfuscatedSessionTicketSharedSecret})

	testMessage := "test"

	result := make(chan error, 1)

	report := func(err error) {
		select {
		case result <- err:
		default:
		}
	}

	listening := make(chan string, 1)

	go func() {

		listener, err := Listen("tcp", ":0", serverConfig, nil)
		if err != nil {
			report(err)
			return
		}
		defer listener.Close()

		listening <- listener.Addr().String()

		conn, err := listener.Accept()
		if err != nil {
			report(err)
			return
		}
		defer conn.Close()

		recv := make([]byte, len(testMessage))
		_, err = io.ReadFull(conn, recv)
		if err == nil && string(recv) != testMessage {
			err = errors.New("unexpected payload")
		}
		if err != nil {
			report(err)
			return
		}

		// Sends nil on success
		report(nil)
	}()

	go func() {

		serverAddress := <-listening

		tcpConn, err := net.Dial("tcp", serverAddress)
		if err != nil {
			report(err)
			return
		}
		defer tcpConn.Close()

		tlsConn := utls.UClient(tcpConn, clientConfig, helloID)

		obfuscatedSessionState, err := NewObfuscatedClientSessionState(
			obfuscatedSessionTicketSharedSecret)
		if err != nil {
			report(err)
			return
		}

		sessionState := utls.MakeClientSessionState(
			obfuscatedSessionState.SessionTicket,
			obfuscatedSessionState.Vers,
			obfuscatedSessionState.CipherSuite,
			obfuscatedSessionState.MasterSecret,
			nil,
			nil)

		tlsConn.SetSessionState(sessionState)

		_, err = tlsConn.Write([]byte(testMessage))
		if err != nil {
			report(err)
			return
		}
	}()

	err = <-result
	if err != nil {
		t.Fatalf("connect failed: %s", err)
	}
}

func generateCertificate() (*Certificate, error) {

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		return nil, err
	}
	subjectKeyID := sha1.Sum(publicKeyBytes)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "www.example.org"},
		NotBefore:             time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:              time.Now().Add(time.Hour).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID[:],
		MaxPathLen:            1,
		Version:               2,
	}

	derCert, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		rsaKey.Public(),
		rsaKey)
	if err != nil {
		return nil, err
	}

	certificate := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derCert,
		},
	)

	privateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	keyPair, err := X509KeyPair(certificate, privateKey)
	if err != nil {
		return nil, err
	}

	return &keyPair, nil
}
