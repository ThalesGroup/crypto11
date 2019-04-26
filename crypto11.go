// Copyright 2016 Thales e-Security, Inc
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

// Package crypto11 enables access to cryptographic keys from PKCS#11 using Go crypto API.
//
// Simple use
//
// 1. Either write a configuration file (see ConfigureFromFile) or
// define a configuration in your application (see Config and
// Configure). This will identify the PKCS#11 library and token to
// use, and contain the password (or "PIN" in PKCS#11 terminology) to
// use. A Context is returned, which is then used to invoke operations
// on the PKCS#11 token.
//
// 2. Create keys with GenerateDSAKeyPairWithLabel, GenerateRSAKeyPair and
// GenerateECDSAKeyPair. The keys you get back implement the standard
// Go crypto.Signer interface (and crypto.Decrypter, for RSA). They
// are automatically persisted under random a randomly generated label
// and ID (use the Identify method to discover them).
//
// 3. Retrieve existing keys with FindKeyPair. The returned value is a
// Go crypto.PrivateKey; it may be converted either to crypto.Signer
// or to *pkcs11PrivateKeyDSA, *pkcs11PrivateKeyECDSA or
// *pkcs11PrivateKeyRSA.
//
// Sessions and concurrency
//
// // Note that PKCS#11 session handles must not be used concurrently
// from multiple threads. Consumers of the Signer interface know
// nothing of this and expect to be able to sign from multiple threads
// without constraint. We address this as follows.
//
// 1. When a Context is created, a session is created and the user is
// logged in. This session remains open until the Context is closed,
// to ensure all object handles remain valid and to avoid repeatedly
// calling C_Login.
//
// 2. The Context maintains a pool of read-write sessions. The pool expands
// dynamically as needed, but never beyond the maximum number of r/w sessions
// supported by the token as reported by C_GetInfo. If other applications
// are using the token, a lower limit should be set (see below).
//
// 3. Each operation transiently takes a session from the pool. They
// have exclusive use of the session, meeting PKCS#11's concurrency
// requirements. Sessions are returned to the pool afterwards and may
// be re-used.
//
// Behaviour of the pool can be tweaked via configuration options:
//
// - PoolWaitTimeout controls how long an operation can block waiting on a
// session from the pool. A zero value means there is no limit. Timeouts only
// occur if the pool is full and additional operations are requested.
//
// - MaxSessions sets an upper bound on the number of sessions. If this value is zero,
// a default maximum is used (see DefaultMaxSessions). In every case the maximum
// supported sessions as reported by the token is obeyed.
//
// Limitations
//
// The PKCS1v15DecryptOptions SessionKeyLen field is not implemented
// and an error is returned if it is nonzero.
// The reason for this is that it is not possible for crypto11 to guarantee the constant-time behavior in the specification.
// See https://github.com/thalesignite/crypto11/issues/5 for further discussion.
//
// Symmetric crypto support via cipher.Block is very slow.
// You can use the BlockModeCloser API
// but you must call the Close() interface (not found in cipher.BlockMode).
// See https://github.com/ThalesIgnite/crypto11/issues/6 for further discussion.
package crypto11

import (
	"crypto"
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"github.com/vitessio/vitess/go/pools"
)

const (
	// DefaultMaxSessions controls the maximum number of concurrent sessions to
	// open, unless otherwise specified in the Config object.
	DefaultMaxSessions = 1024
)

// ErrTokenNotFound represents the failure to find the requested PKCS#11 token
var ErrTokenNotFound = errors.New("crypto11: could not find PKCS#11 token")

// ErrKeyNotFound represents the failure to find the requested PKCS#11 key
var ErrKeyNotFound = errors.New("crypto11: could not find PKCS#11 key")

// ErrCannotOpenPKCS11 is returned when the PKCS#11 library cannot be opened
var ErrCannotOpenPKCS11 = errors.New("crypto11: could not open PKCS#11")

// ErrCannotGetRandomData is returned when the PKCS#11 library fails to return enough random data
var ErrCannotGetRandomData = errors.New("crypto11: cannot get random data from PKCS#11")

// ErrUnsupportedKeyType is returned when the PKCS#11 library returns a key type that isn't supported
var ErrUnsupportedKeyType = errors.New("crypto11: unrecognized key type")

// ErrClosed is returned if a Context is used after a call to Close.
var ErrClosed = errors.New("crypto11: cannot used closed Context")

// pkcs11Object contains a reference to a loaded PKCS#11 object.
type pkcs11Object struct {
	// TODO - handle resource cleanup. Consider adding explicit Close method and/or use a finalizer

	// The PKCS#11 object handle.
	handle pkcs11.ObjectHandle

	// The PKCS#11 context. This is used  to find a session handle that can
	// access this object.
	context *Context
}

func (o *pkcs11Object) Delete() error {
	return o.context.withSession(func(session *pkcs11Session) error {
		err := session.ctx.DestroyObject(session.handle, o.handle)
		return errors.WithMessage(err, "crypto11: failed to destroy key")
	})
}

// pkcs11PrivateKey contains a reference to a loaded PKCS#11 private key object.
type pkcs11PrivateKey struct {
	pkcs11Object

	// pubKeyHandle is a handle to the public key.
	pubKeyHandle pkcs11.ObjectHandle

	// pubKey is an exported copy of the public key. We pre-export the key material because crypto.Signer.Public
	// doesn't allow us to return errors.
	pubKey crypto.PublicKey
}

// Delete implements Signer.Delete.
func (k *pkcs11PrivateKey) Delete() error {
	err := k.pkcs11Object.Delete()
	if err != nil {
		return err
	}

	return k.context.withSession(func(session *pkcs11Session) error {
		err := session.ctx.DestroyObject(session.handle, k.pubKeyHandle)
		return errors.WithMessage(err, "crypto11: failed to destroy public key")
	})
}

// A Context stores the connection state to a PKCS#11 token. Use Configure or ConfigureFromFile to create a new
// Context. Call Close when finished with the token, to free up resources.
//
// All functions, except Close, are safe to call from multiple goroutines.
type Context struct {
	ctx *pkcs11.Ctx
	cfg *Config

	token *pkcs11.TokenInfo
	slot  uint
	pool  *pools.ResourcePool

	// persistentSession is a session held open so we can be confident handles and login status
	// persist for the duration of this context
	persistentSession pkcs11.SessionHandle
}

// Signer is a PKCS#11 key that implements crypto.Signer.
type Signer interface {
	crypto.Signer

	// Delete deletes the key pair from the token.
	Delete() error
}

// SignerDecrypter is a PKCS#11 key implements crypto.Signer and crypto.Decrypter.
type SignerDecrypter interface {
	Signer

	// Decrypt implements crypto.Decrypter.
	Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
}

// findToken finds a token given its serial number
func (c *Context) findToken(slots []uint, serial string, label string) (uint, *pkcs11.TokenInfo, error) {
	for _, slot := range slots {
		tokenInfo, err := c.ctx.GetTokenInfo(slot)
		if err != nil {
			return 0, nil, err
		}
		if tokenInfo.SerialNumber == serial {
			return slot, &tokenInfo, nil
		}
		if tokenInfo.Label == label {
			return slot, &tokenInfo, nil
		}
	}
	return 0, nil, ErrTokenNotFound
}

// Config holds PKCS#11 configuration information.
//
// A token may be identified either by serial number or label.  If
// both are specified then the first match wins.
//
// Supply this to Configure(), or alternatively use ConfigureFromFile().
type Config struct {
	// Full path to PKCS#11 library.
	Path string

	// Token serial number.
	TokenSerial string

	// Token label.
	TokenLabel string

	// User PIN (password).
	Pin string

	// Maximum number of concurrent sessions to open. If zero, DefaultMaxSessions is used.
	MaxSessions int

	// Maximum time to wait for a session from the sessions pool. Zero means wait indefinitely.
	PoolWaitTimeout time.Duration
}

// Configure creates a new Context based on the supplied PKCS#11 configuration.
func Configure(config *Config) (*Context, error) {
	if config.MaxSessions == 0 {
		config.MaxSessions = DefaultMaxSessions
	}

	instance := &Context{
		cfg: config,
		ctx: pkcs11.New(config.Path),
	}

	if instance.ctx == nil {
		log.Printf("Could not open PKCS#11 library: %s", config.Path)
		return nil, ErrCannotOpenPKCS11
	}
	if err := instance.ctx.Initialize(); err != nil {
		log.Printf("Failed to initialize PKCS#11 library: %s", err.Error())
		return nil, err
	}
	slots, err := instance.ctx.GetSlotList(true)
	if err != nil {
		log.Printf("Failed to list PKCS#11 Slots: %s", err.Error())
		return nil, err
	}

	instance.slot, instance.token, err = instance.findToken(slots, config.TokenSerial, config.TokenLabel)
	if err != nil {
		log.Printf("Failed to find Token in any Slot: %s", err.Error())
		return nil, err
	}

	// Create the session pool.
	// TODO - remove these when https://github.com/miekg/pkcs11/pull/115/ is merged
	const ckEffectivelyInfinite = 0
	const ckUnavailableInformation = ^uint(0)

	maxSessions := instance.cfg.MaxSessions
	tokenMaxSessions := instance.token.MaxRwSessionCount
	if tokenMaxSessions != ckEffectivelyInfinite && tokenMaxSessions != ckUnavailableInformation {
		maxSessions = min(maxSessions, castDown(tokenMaxSessions))
	}

	// We will use one session to keep state alive, so the pool gets maxSessions - 1
	instance.pool = pools.NewResourcePool(instance.resourcePoolFactoryFunc, maxSessions-1, maxSessions-1, 0)

	// Create a long-term session and log it in. This session won't be used by callers, instead it is used to keep
	// a connection alive to the token to ensure object handles and the log in status remain accessible.
	instance.persistentSession, err = instance.ctx.OpenSession(instance.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, errors.WithMessagef(err, "crypto11: failed to create long term session")
	}
	err = instance.ctx.Login(instance.persistentSession, pkcs11.CKU_USER, instance.cfg.Pin)
	if err != nil {
		return nil, errors.WithMessagef(err, "crypto11: failed to log into long term session")
	}

	return instance, nil
}

func min(a, b int) int {
	if b < a {
		return b
	}
	return a
}

// castDown returns orig as a signed integer. If an overflow would have occurred,
// the maximum possible value is returned.
func castDown(orig uint) int {
	// From https://stackoverflow.com/a/6878625/474189
	const maxUint = ^uint(0)
	const maxInt = int(maxUint >> 1)

	if orig > uint(maxInt) {
		return maxInt
	}

	return int(orig)
}

// ConfigureFromFile is a convenience method, which parses the configuration file
// and calls Configure. The configuration file should be a JSON representation
// of a Config object.
func ConfigureFromFile(configLocation string) (*Context, error) {
	config, err := loadConfigFromFile(configLocation)
	if err != nil {
		return nil, err
	}

	return Configure(config)
}

// loadConfigFromFile reads a Config struct from a file.
func loadConfigFromFile(configLocation string) (*Config, error) {
	file, err := os.Open(configLocation)
	if err != nil {
		return nil, errors.WithMessagef(err, "could not open config file: %s", configLocation)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}()

	configDecoder := json.NewDecoder(file)
	config := &Config{}
	err = configDecoder.Decode(config)
	return config, errors.WithMessage(err, "could decode config file:")
}

// Close releases all the resources used by the Context and unloads the PKCS #11 library. Close blocks until existing
// operations have finished. A closed Context cannot be reused.
func (c *Context) Close() error {

	// Block until all resources returned to pool
	c.pool.Close()

	// Close our long-term session. We ignore any returned error,
	// since we plan to kill our collection to the library anyway.
	_ = c.ctx.CloseSession(c.persistentSession)

	err := c.ctx.Finalize()
	if err != nil {
		return err
	}

	c.ctx.Destroy()
	return nil
}
