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
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"github.com/miekg/pkcs11"
	"testing"
)

func TestHardSymmetric(t *testing.T) {
	ConfigureFromFile("config")
	t.Run("AES128", func(t *testing.T) { testHardSymmetric(t, pkcs11.CKK_AES, 128) })
	t.Run("AES192", func(t *testing.T) { testHardSymmetric(t, pkcs11.CKK_AES, 192) })
	t.Run("AES256", func(t *testing.T) { testHardSymmetric(t, pkcs11.CKK_AES, 256) })
	t.Run("DES3", func(t *testing.T) { testHardSymmetric(t, pkcs11.CKK_DES3, 0) })
	Close()
}

func testHardSymmetric(t *testing.T, keytype int, bits int) {
	var err error
	var key *PKCS11SecretKey
	var id []byte
	t.Run("Generate", func(t *testing.T) {
		if key, err = GenerateSecretKey(bits, Ciphers[keytype]); err != nil {
			t.Errorf("crypto11.GenerateSecretKey: %v", err)
			return
		}
		if key == nil {
			t.Errorf("crypto11.GenerateSecretKey: returned nil but no error")
			return
		}
		if id, _, err = key.Identify(); err != nil {
			t.Errorf("crypto11.PKCS11SecretKey.Identify: %v", err)
			return
		}
	})
	var key2 crypto.PrivateKey
	t.Run("Find", func(t *testing.T) {
		if key2, err = FindKey(id, nil); err != nil {
			t.Errorf("crypto11.FindKey by id: %v", err)
			return
		}
	})
	t.Run("Block", func(t *testing.T) { testSymmetricBlock(t, key, key2.(*PKCS11SecretKey)) })
	iv := make([]byte, key.BlockSize())
	if _, err = rand.Read(iv); err != nil {
		t.Errorf("rand.Read: %v", err)
		return
	}
	t.Run("CBC", func(t *testing.T) {
		testSymmetricMode(t, cipher.NewCBCEncrypter(key2.(*PKCS11SecretKey), iv), cipher.NewCBCDecrypter(key2.(*PKCS11SecretKey), iv))
	})
	// TODO perf test native CBC vs idiomatic PKCS#11 CBC
	// TODO CFB
	// TODO OFB
	// TODO CTR
	// TODO GCM
}

func testSymmetricBlock(t *testing.T, encryptKey cipher.Block, decryptKey cipher.Block) {
	b := encryptKey.BlockSize()
	input := make([]byte, 3*b)
	middle := make([]byte, 3*b)
	output := make([]byte, 3*b)
	// Set a recognizable pattern in the buffers
	for i := 0; i < 3*b; i++ {
		input[i] = byte(i)
		middle[i] = byte(i + 3*b)
		output[i] = byte(i + 6*b)
	}
	encryptKey.Encrypt(middle, input) // middle[:b] = encrypt(input[:b])
	if bytes.Compare(input[:b], middle[:b]) == 0 {
		t.Errorf("crypto11.PKCSSecretKey.Encrypt: identity transformation")
		return
	}
	matches := 0
	for i := 0; i < b; i++ {
		if middle[i] == byte(i+3*b) {
			matches++
		}
	}
	if matches == b {
		t.Errorf("crypto11.PKCSSecretKey.Encrypt: didn't modify destination")
		return
	}
	for i := 0; i < 3*b; i++ {
		if input[i] != byte(i) {
			t.Errorf("crypto11.PKCSSecretKey.Encrypt: corrupted source")
			return
		}
		if i >= b && middle[i] != byte(i+3*b) {
			t.Errorf("crypto11.PKCSSecretKey.Encrypt: corrupted destination past blocksize")
			return
		}
	}
	decryptKey.Decrypt(output, middle) // output[:b] = decrypt(middle[:b])
	if bytes.Compare(input[:b], output[:b]) != 0 {
		t.Errorf("crypto11.PKCSSecretKey.Decrypt: plaintext wrong")
		return
	}
	for i := 0; i < 3*b; i++ {
		if i >= b && output[i] != byte(i+6*b) {
			t.Errorf("crypto11.PKCSSecretKey.Decrypt: corrupted destination past blocksize")
			return
		}
	}
}

func testSymmetricMode(t *testing.T, encrypt cipher.BlockMode, decrypt cipher.BlockMode) {
	input := make([]byte, 256)
	middle := make([]byte, 256)
	output := make([]byte, 256)
	// Set a recognizable pattern in the buffers
	for i := 0; i < 256; i++ {
		input[i] = byte(i)
		middle[i] = byte(i + 32)
		output[i] = byte(i + 64)
	}
	// Encrypt the first 128 bytes
	encrypt.CryptBlocks(middle, input[:128])
	if bytes.Compare(input[:128], middle[:128]) == 0 {
		t.Errorf("BlockMode.Encrypt: did not modify destination")
		return
	}
	for i := 0; i < 128; i++ {
		if input[i] != byte(i) {
			t.Errorf("BlockMode.Encrypt: corrupted source")
			return
		}
	}
	for i := 128; i < 256; i++ {
		if middle[i] != byte(i+32) {
			t.Errorf("BlockMode.Encrypt: corrupted destination past input size")
			return
		}
	}
	// Encrypt the rest
	encrypt.CryptBlocks(middle[128:], input[128:])
	// Decrypt in a single go
	decrypt.CryptBlocks(output, middle)
	if bytes.Compare(input, output) != 0 {
		t.Errorf("BlockMode.Decrypt: plaintext wrong")
		return
	}
}
