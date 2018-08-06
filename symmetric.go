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
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/youtube/vitess/go/pools"
	"runtime"
)

const (
	// PaddingNone represents a block cipher with no padding.
	PaddingNone = iota

	// PaddingPKCS represents a block cipher used with PKCS#7 padding.
	PaddingPKCS
)

// SymmetricGenParams holds a consistent (key type, mechanism) key generation pair.
type SymmetricGenParams struct {
	// Key type (CKK_...)
	KeyType uint

	// Key generation mechanism (CKM_..._KEY_GEN)
	GenMech uint
}

// SymmetricCipher represents information about a symmetric cipher.
type SymmetricCipher struct {
	// Possible key generation parameters
	// (For HMAC this varies between PKCS#11 implementations.)
	GenParams []SymmetricGenParams

	// Block size in bytes
	BlockSize int

	// True if encryption supported
	Encrypt bool

	// True if MAC supported
	MAC bool

	// ECB mechanism (CKM_..._ECB)
	ECBMech uint

	// CBC mechanism (CKM_..._CBC)
	CBCMech uint

	// CBC mechanism with PKCS#7 padding (CKM_..._CBC)
	CBCPKCSMech uint

	// GCM mechanism (CKM_..._GCM)
	GCMMech uint
}

// CipherAES describes the AES cipher. Use this with the
// GenerateSecretKey... functions.
var CipherAES = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_AES,
			GenMech: pkcs11.CKM_AES_KEY_GEN,
		},
	},
	BlockSize:   16,
	Encrypt:     true,
	MAC:         false,
	ECBMech:     pkcs11.CKM_AES_ECB,
	CBCMech:     pkcs11.CKM_AES_CBC,
	CBCPKCSMech: pkcs11.CKM_AES_CBC_PAD,
	GCMMech:     pkcs11.CKM_AES_GCM,
}

// CipherDES3 describes the three-key triple-DES cipher. Use this with the
// GenerateSecretKey... functions.
var CipherDES3 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_DES3,
			GenMech: pkcs11.CKM_DES3_KEY_GEN,
		},
	},
	BlockSize:   8,
	Encrypt:     true,
	MAC:         false,
	ECBMech:     pkcs11.CKM_DES3_ECB,
	CBCMech:     pkcs11.CKM_DES3_CBC,
	CBCPKCSMech: pkcs11.CKM_DES3_CBC_PAD,
	GCMMech:     0,
}

// CipherGeneric describes the CKK_GENERIC_SECRET key type. Use this with the
// GenerateSecretKey... functions.
//
// The spec promises that this mechanism can be used to perform HMAC
// operations, although implementations vary;
// CipherHMACSHA1 and so on may give better results.
var CipherGeneric = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA1 describes the CKK_SHA_1_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA1 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA_1_HMAC,
			GenMech: CKM_NC_SHA_1_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA224 describes the CKK_SHA224_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA224 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA224_HMAC,
			GenMech: CKM_NC_SHA224_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA256 describes the CKK_SHA256_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA256 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA256_HMAC,
			GenMech: CKM_NC_SHA256_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA384 describes the CKK_SHA384_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA384 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA384_HMAC,
			GenMech: CKM_NC_SHA384_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA512 describes the CKK_SHA512_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA512 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA512_HMAC,
			GenMech: CKM_NC_SHA512_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 128,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// Ciphers is a map of PKCS#11 key types (CKK_...) to symmetric cipher information.
var Ciphers = map[int]*SymmetricCipher{
	pkcs11.CKK_AES:            &CipherAES,
	pkcs11.CKK_DES3:           &CipherDES3,
	pkcs11.CKK_GENERIC_SECRET: &CipherGeneric,
	pkcs11.CKK_SHA_1_HMAC:     &CipherHMACSHA1,
	pkcs11.CKK_SHA224_HMAC:    &CipherHMACSHA224,
	pkcs11.CKK_SHA256_HMAC:    &CipherHMACSHA256,
	pkcs11.CKK_SHA384_HMAC:    &CipherHMACSHA384,
	pkcs11.CKK_SHA512_HMAC:    &CipherHMACSHA512,
}

// PKCS11SecretKey contains a reference to a loaded PKCS#11 symmetric key object.
//
// A *PKCS11SecretKey implements the cipher.Block interface, allowing it be used
// as the argument to cipher.NewCBCDecrypter, etc.
type PKCS11SecretKey struct {
	PKCS11Object

	// Symmetric cipher information
	Cipher *SymmetricCipher
}

// Key generation -------------------------------------------------------------

// GenerateSecretKey creates an secret key of given length and type.
//
// The key will have a random label and ID.
func GenerateSecretKey(bits int, cipher *SymmetricCipher) (*PKCS11SecretKey, error) {
	return GenerateSecretKeyOnSlot(instance.slot, nil, nil, bits, cipher)
}

// GenerateSecretKeyOnSlot creates as symmetric key on a specified slot
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateSecretKeyOnSlot(slot uint, id []byte, label []byte, bits int, cipher *SymmetricCipher) (*PKCS11SecretKey, error) {
	var k *PKCS11SecretKey
	var err error
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		k, err = GenerateSecretKeyOnSession(session, slot, id, label, bits, cipher)
		return err
	})
	return k, err
}

// GenerateSecretKeyOnSession creates a symmetric key of given type and
// length, on a specified session.
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateSecretKeyOnSession(session *PKCS11Session, slot uint, id []byte, label []byte, bits int, cipher *SymmetricCipher) (key *PKCS11SecretKey, err error) {
	// TODO refactor with the other key generation implementations
	if label == nil {
		if label, err = generateKeyLabel(); err != nil {
			return nil, err
		}
	}
	if id == nil {
		if id, err = generateKeyLabel(); err != nil {
			return nil, err
		}
	}
	var privHandle pkcs11.ObjectHandle
	// CKK_*_HMAC exists but there is no specific corresponding CKM_*_KEY_GEN
	// mechanism. Therefore we attempt both CKM_GENERIC_SECRET_KEY_GEN and
	// vendor-specific mechanisms.
	for _, genMech := range cipher.GenParams {
		secretKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, genMech.KeyType),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, cipher.MAC),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, cipher.MAC),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, cipher.Encrypt),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, cipher.Encrypt),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
		if bits > 0 {
			secretKeyTemplate = append(secretKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, bits/8))
		}
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(genMech.GenMech, nil)}
		privHandle, err = session.Ctx.GenerateKey(session.Handle, mech, secretKeyTemplate)
		if err == nil {
			break
		}
		// nShield returns this if if doesn't like the CKK/CKM combination.
		if e, ok := err.(pkcs11.Error); ok && e == pkcs11.CKR_TEMPLATE_INCONSISTENT {
			continue
		}
		if err != nil {
			return
		}
	}
	if err != nil {
		return
	}
	key = &PKCS11SecretKey{PKCS11Object{privHandle, slot}, cipher}
	return
}

// cipher.Block ---------------------------------------------------------

// BlockSize returns the cipher's block size in bytes.
func (key *PKCS11SecretKey) BlockSize() int {
	return key.Cipher.BlockSize
}

// Decrypt decrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (key *PKCS11SecretKey) Decrypt(dst, src []byte) {
	var result []byte
	if err := withSession(key.Slot, func(session *PKCS11Session) (err error) {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(key.Cipher.ECBMech, nil)}
		if err = session.Ctx.DecryptInit(session.Handle, mech, key.Handle); err != nil {
			return
		}
		if result, err = session.Ctx.Decrypt(session.Handle, src[:key.Cipher.BlockSize]); err != nil {
			return
		}
		if len(result) != key.Cipher.BlockSize {
			err = fmt.Errorf("C_Decrypt: returned %v bytes, wanted %v", len(result), key.Cipher.BlockSize)
			return
		}
		return
	}); err != nil {
		panic(err)
	} else {
		copy(dst[:key.Cipher.BlockSize], result)
	}
}

// Encrypt encrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (key *PKCS11SecretKey) Encrypt(dst, src []byte) {
	var result []byte
	if err := withSession(key.Slot, func(session *PKCS11Session) (err error) {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(key.Cipher.ECBMech, nil)}
		if err = session.Ctx.EncryptInit(session.Handle, mech, key.Handle); err != nil {
			return
		}
		if result, err = session.Ctx.Encrypt(session.Handle, src[:key.Cipher.BlockSize]); err != nil {
			return
		}
		if len(result) != key.Cipher.BlockSize {
			err = fmt.Errorf("C_Encrypt: unexpectedly returned %v bytes, wanted %v", len(result), key.Cipher.BlockSize)
			return
		}
		return
	}); err != nil {
		panic(err)
	} else {
		copy(dst[:key.Cipher.BlockSize], result)
	}
}

// cipher.AEAD ----------------------------------------------------------

type genericAead struct {
	key *PKCS11SecretKey

	overhead int

	nonceSize int

	makeMech func(nonce []byte, additionalData []byte) ([]*pkcs11.Mechanism, error)
}

// NewGCM returns a given cipher wrapped in Galois Counter Mode, with the standard
// nonce length.
//
// This depends on the HSM supporting the CKM_*_GCM mechanism. If it is not supported
// then you must use cipher.NewGCM; it will be slow.
func (key *PKCS11SecretKey) NewGCM() (g cipher.AEAD, err error) {
	if key.Cipher.GCMMech == 0 {
		err = fmt.Errorf("GCM not implemented for key type %#x", key.Cipher.GenParams[0].KeyType)
		return
	}
	g = genericAead{
		key:       key,
		overhead:  16,
		nonceSize: 12,
		makeMech: func(nonce []byte, additionalData []byte) (mech []*pkcs11.Mechanism, error error) {
			params := pkcs11.NewGCMParams(nonce, additionalData, 16)
			mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(key.Cipher.GCMMech, params)}
			return
		},
	}
	return
}

// NewCBC returns a given cipher wrapped in CBC mode.
//
// Despite the cipher.AEAD return type, there is no support for additional data and no authentication.
// This method exists to provide a convenient way to do bulk (possibly padded) CBC encryption.
// Think carefully before passing the cipher.AEAD to any consumer that expects authentication.
func (key *PKCS11SecretKey) NewCBC(paddingMode int) (g cipher.AEAD, err error) {
	g = genericAead{
		key:       key,
		overhead:  0,
		nonceSize: key.BlockSize(),
		makeMech: func(nonce []byte, additionalData []byte) (mech []*pkcs11.Mechanism, error error) {
			if len(additionalData) > 0 {
				err = errors.New("additional data not supported for CBC mode")
			}
			var pkcsMech uint
			switch paddingMode {
			case PaddingNone:
				pkcsMech = key.Cipher.CBCMech
			case PaddingPKCS:
				pkcsMech = key.Cipher.CBCPKCSMech
			default:
				err = errors.New("unrecognized padding mode")
				return
			}
			if pkcsMech == 0 {
				err = errors.New("unsupported padding mode")
				return
			}
			mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcsMech, nonce)}
			return
		},
	}
	return
}

func (g genericAead) NonceSize() int {
	return g.nonceSize
}

func (g genericAead) Overhead() int {
	return g.overhead
}

func (g genericAead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var result []byte
	if err := withSession(g.key.Slot, func(session *PKCS11Session) (err error) {
		var mech []*pkcs11.Mechanism
		if mech, err = g.makeMech(nonce, additionalData); err != nil {
			return
		}
		if err = session.Ctx.EncryptInit(session.Handle, mech, g.key.Handle); err != nil {
			err = fmt.Errorf("C_EncryptInit: %v", err)
			return
		}
		if result, err = session.Ctx.Encrypt(session.Handle, plaintext); err != nil {
			err = fmt.Errorf("C_Encrypt: %v", err)
			return
		}
		return
	}); err != nil {
		panic(err)
	} else {
		dst = append(dst, result...)
	}
	return dst
}

func (g genericAead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var result []byte
	if err := withSession(g.key.Slot, func(session *PKCS11Session) (err error) {
		var mech []*pkcs11.Mechanism
		if mech, err = g.makeMech(nonce, additionalData); err != nil {
			return
		}
		if err = session.Ctx.DecryptInit(session.Handle, mech, g.key.Handle); err != nil {
			err = fmt.Errorf("C_DecryptInit: %v", err)
			return
		}
		if result, err = session.Ctx.Decrypt(session.Handle, ciphertext); err != nil {
			err = fmt.Errorf("C_Decrypt: %v", err)
			return
		}
		return
	}); err != nil {
		return nil, err
	}
	dst = append(dst, result...)
	return dst, nil
}

// Stream encryption/decryption -----------------------------------------

// BlockModeCloser represents a block cipher running in a block-based mode (CBC, ECB etc).
//
// BlockModeCloser implements cipher.BlockMode, and can be used as such.
// However, in this case
// (or if the Close() method is not explicitly called for any other reason),
// resources allocated to it may remain live longer than necessary.
//
// The underlying implementations set a finalizer
// so these resources will eventually be released,
// but if your application has resource consumption problems or hangs
// then adding an explicit Close() call may be the solution.
// If that is not possible then adding calls to runtime.GC() may help.
type BlockModeCloser interface {
	cipher.BlockMode

	// Close() releases resources associated with the block mode.
	Close()
}

const (
	modeEncrypt = iota // blockModeCloser is in encrypt mode
	modeDecrypt        // blockModeCloser is in decrypt mode
)

// NewCBCEncrypter returns a cipher.BlockMode which encrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size.
//
// The new BlockMode acquires persistent resources which are released (eventually) by a finalizer.
// If this is a problem for your application then use NewCBCEncrypterCloser instead.
func (key *PKCS11SecretKey) NewCBCEncrypter(iv []byte) (bm cipher.BlockMode, err error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeEncrypt, iv, true)
}

// NewCBCDecrypter returns a cipher.BlockMode which decrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size and must match the iv used to encrypt the data.
//
// The new BlockMode acquires persistent resources which are released (eventually) by a finalizer.
// If this is a problem for your application then use NewCBCDecrypterCloser instead.
func (key *PKCS11SecretKey) NewCBCDecrypter(iv []byte) (bm cipher.BlockMode, err error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeDecrypt, iv, true)
}

// NewCBCEncrypterCloser returns a  BlockModeCloser which encrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size.
func (key *PKCS11SecretKey) NewCBCEncrypterCloser(iv []byte) (bmc BlockModeCloser, err error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeEncrypt, iv, false)
}

// NewCBCDecrypterCloser returns a  BlockModeCloser which decrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size and must match the iv used to encrypt the data.
func (key *PKCS11SecretKey) NewCBCDecrypterCloser(iv []byte) (bmc BlockModeCloser, err error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeDecrypt, iv, false)
}

// blockModeCloser is a concrete implementation of BlockModeCloser supporting CBC.
type blockModeCloser struct {
	// PKCS#11 session to use
	session *PKCS11Session

	// Cipher block size
	blockSize int

	// modeDecrypt or modeEncrypt
	mode int

	// Cleanup function
	cleanup func()
}

// newBlockModeCloser creates a new blockModeCloser for the chosen mechanism and mode.
func (key *PKCS11SecretKey) newBlockModeCloser(mech uint, mode int, iv []byte, setFinalizer bool) (bmc *blockModeCloser, err error) {
	// TODO maybe refactor with withSession()
	sessionPool := pool.Get(key.Slot)
	if sessionPool == nil {
		err = fmt.Errorf("crypto11: no session for slot %d", key.Slot)
		return
	}
	ctx := context.Background()
	if instance.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), instance.cfg.PoolWaitTimeout)
		defer cancel()
	}
	var session pools.Resource
	if session, err = sessionPool.Get(ctx); err != nil {
		return
	}
	bmc = &blockModeCloser{
		session:   session.(*PKCS11Session),
		blockSize: key.Cipher.BlockSize,
		mode:      mode,
		cleanup: func() {
			sessionPool.Put(session)
		},
	}
	mechDescription := []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, iv)}
	switch mode {
	case modeDecrypt:
		err = bmc.session.Ctx.DecryptInit(bmc.session.Handle, mechDescription, key.Handle)
	case modeEncrypt:
		err = bmc.session.Ctx.EncryptInit(bmc.session.Handle, mechDescription, key.Handle)
	default:
		panic("unexpected mode")
	}
	if err != nil {
		bmc.cleanup()
		return
	}
	if setFinalizer {
		runtime.SetFinalizer(bmc, finalizeBlockModeCloser)
	}
	return
}

func finalizeBlockModeCloser(obj interface{}) {
	obj.(*blockModeCloser).Close()
}

func (bmc *blockModeCloser) BlockSize() int {
	return bmc.blockSize
}

func (bmc *blockModeCloser) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("destination buffer too small")
	}
	if len(src)%bmc.blockSize != 0 {
		panic("input is not a whole number of blocks")
	}
	var result []byte
	var err error
	switch bmc.mode {
	case modeDecrypt:
		result, err = bmc.session.Ctx.DecryptUpdate(bmc.session.Handle, src)
	case modeEncrypt:
		result, err = bmc.session.Ctx.EncryptUpdate(bmc.session.Handle, src)
	}
	if err != nil {
		panic(err)
	}
	// PKCS#11 2.40 s5.2 says that the operation must produce as much output
	// as possible, so we should never have less than we submitted for CBC.
	// This could be different for other modes but we don't implement any yet.
	if len(result) != len(src) {
		panic("nontrivial result from *Final operation")
	}
	copy(dst[:len(result)], result)
}

func (bmc *blockModeCloser) Close() {
	if bmc.session == nil {
		return
	}
	var result []byte
	var err error
	switch bmc.mode {
	case modeDecrypt:
		result, err = bmc.session.Ctx.DecryptFinal(bmc.session.Handle)
	case modeEncrypt:
		result, err = bmc.session.Ctx.EncryptFinal(bmc.session.Handle)
	}
	bmc.session = nil
	bmc.cleanup()
	if err != nil {
		panic(err)
	}
	// PKCS#11 2.40 s5.2 says that the operation must produce as much output
	// as possible, so we should never have any left over for CBC.
	// This could be different for other modes but we don't implement any yet.
	if len(result) > 0 {
		panic("nontrivial result from *Final operation")
	}
}
