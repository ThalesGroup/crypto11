// Copyright 2016, 2017 Thales e-Security, Inc
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
	"crypto/dsa"
	"encoding/json"
	"fmt"
	"github.com/miekg/pkcs11"
	"log"
	"os"
	"testing"
	"time"
)

func TestInitializeFromConfig(t *testing.T) {
	var config PKCS11Config
	config.Path = "NoSuchFile"
	config.Pin = "NoSuchPin"
	config.TokenSerial = "NoSuchToken"
	config.TokenLabel = "NoSuchToken"
	//assert.Panics(Configure(config), "Invalid config should panic")
	ConfigureFromFile("config")
	Close()
}

func TestLoginContext(t *testing.T) {
	t.Run("key identity with login", func(t *testing.T) {
		configureWithPin(t)
		defer Close()

		// Generate a key and and close a session
		var err error
		var key *PKCS11PrivateKeyDSA
		psize := dsa.L1024N160
		if key, err = GenerateDSAKeyPair(dsaSizes[psize]); err != nil {
			t.Errorf("crypto11.GenerateDSAKeyPair: %v", err)
			return
		}
		if key == nil {
			t.Errorf("crypto11.dsa.GenerateDSAKeyPair: returned nil but no error")
			return
		}

		var id []byte
		if id, _, err = key.Identify(); err != nil {
			t.Errorf("crypto11.dsa.PKCS11PrivateKeyDSA.Identify: %v", err)
			return
		}
		if err = Close(); err != nil {
			t.Fatal(err)
		}

		// Reopen a session and try to find a key.
		// Valid session must enlist a key.
		// If login is not performed than it will fail.
		configureWithPin(t)

		var key2 crypto.PrivateKey
		if key2, err = FindKeyPair(id, nil); err != nil {
			t.Errorf("crypto11.dsa.FindDSAKeyPair by id: %v", err)
			return
		}
		testDsaSigning(t, key2.(*PKCS11PrivateKeyDSA), psize, fmt.Sprintf("close%d", 0))
	})

	t.Run("key identity with expiration", func(t *testing.T) {
		prevIdleTimeout := instance.idleTimeout
		defer func() {instance.idleTimeout = prevIdleTimeout}()
		instance.idleTimeout = time.Second

		configureWithPin(t)
		defer Close()

		// Generate a key and and close a session
		var err error
		var key *PKCS11PrivateKeyDSA
		psize := dsa.L1024N160
		if key, err = GenerateDSAKeyPair(dsaSizes[psize]); err != nil {
			t.Errorf("crypto11.GenerateDSAKeyPair: %v", err)
			return
		}
		if key == nil {
			t.Errorf("crypto11.dsa.GenerateDSAKeyPair: returned nil but no error")
			return
		}

		var id []byte
		if id, _, err = key.Identify(); err != nil {
			t.Errorf("crypto11.dsa.PKCS11PrivateKeyDSA.Identify: %v", err)
			return
		}

		// kick out all idle sessions
		time.Sleep(instance.idleTimeout + time.Second)

		// Reopen a session and try to find a key.
		// Valid session must enlist a key.
		// If login is not performed than it will fail.
		configureWithPin(t)

		var key2 crypto.PrivateKey
		if key2, err = FindKeyPair(id, nil); err != nil {
			t.Errorf("crypto11.dsa.FindDSAKeyPair by id: %v", err)
			return
		}
		testDsaSigning(t, key2.(*PKCS11PrivateKeyDSA), psize, fmt.Sprintf("close%d", 0))
	})
}

func configureWithPin(t *testing.T) (*pkcs11.Ctx, error) {
	cfg, err := getConfig("config")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Pin == "" {
		t.Fatal("invalid configuration. configuration must have PIN non empty.")
	}

	ctx, err := Configure(cfg)
	if err != nil {
		t.Fatal("failed to configure service:", err)
	}

	return ctx, nil
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

