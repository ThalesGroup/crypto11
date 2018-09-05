// Copyright 2018 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/miekg/pkcs11"
	"log"
	"os"
	"testing"
	"time"
)

func TestPoolTimeout(t *testing.T) {
	t.Run("first login", func(t *testing.T) {
		prevIdleTimeout := idleTimeout
		defer func() {idleTimeout = prevIdleTimeout}()
		idleTimeout = time.Second

		cfg, err := getConfig("config")
		if err != nil {
			t.Fatal(err)
		}

		if cfg.Pin == "" {
			t.Fatal("invalid configuration. configuration must have PIN non empty.")
		}

		_, err = Configure(cfg)
		if err != nil {
			t.Fatal("failed to configure service:", err)
		}
		defer Close()

		time.Sleep(idleTimeout + time.Second)

		_, err = GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			if perr, ok := err.(pkcs11.Error); ok && perr == pkcs11.CKR_USER_NOT_LOGGED_IN {
				t.Fatal("pool handle session incorrectly, login required but missing:", err)
			} else {
				t.Fatal("failed to generate a key, unexpected error:", err)
			}
		}
	})

	t.Run("reuse expired handle", func(t *testing.T) {
		prevIdleTimeout := idleTimeout
		defer func() {idleTimeout = prevIdleTimeout}()
		idleTimeout = time.Second

		cfg, err := getConfig("config")
		if err != nil {
			t.Fatal(err)
		}

		if cfg.Pin == "" {
			t.Fatal("invalid configuration. configuration must have PIN non empty.")
		}

		_, err = Configure(cfg)
		if err != nil {
			t.Fatal("failed to configure service:", err)
		}
		defer Close()

		key, err := GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			t.Fatal("failed to generate a key:", err)
		}

		time.Sleep(idleTimeout + time.Second)

		_, err = key.Sign(rand.Reader, crypto.SHA256.New().Sum([]byte("sha256")), crypto.SHA256)
		if err != nil {
			if perr, ok := err.(pkcs11.Error); ok && perr == pkcs11.CKR_OBJECT_HANDLE_INVALID {
				t.Fatal("pool handle session incorrectly, login required but missing:", err)
			} else {
				t.Fatal("failed to reuse existing key handle, unexpected error:", err)
			}
		}
	})
}

func getConfig(configLocation string) (*PKCS11Config, error) {
	file, err := os.Open(configLocation)
	if err != nil {
		log.Printf("Could not open config file: %s", configLocation)
		return nil, err
	}
	defer file.Close()
	configDecoder := json.NewDecoder(file)
	config := &PKCS11Config{}
	err = configDecoder.Decode(config)
	if err != nil {
		log.Printf("Could decode config file: %s", err.Error())
		return nil, err
	}
	return config, nil
}

