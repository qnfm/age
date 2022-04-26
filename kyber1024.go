// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"github.com/cloudflare/circl/pke/kyber/kyber1024"
	"golang.org/x/crypto/sha3"
)

const Kyber1024Label = "age-encryption.org/v3/Kyber1024"

// Kyber1024Recipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding Kyber1024Identity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type Kyber1024Recipient struct {
	theirPublicKey []byte
}

var _ Recipient = &Kyber1024Recipient{}

// ParseKyber1024Recipient returns a new Kyber1024Recipient from a raw string without any encoding
func ParseKyber1024Recipient(s string) (*Kyber1024Recipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}

	return &Kyber1024Recipient{theirPublicKey: k}, nil
}

func (r *Kyber1024Recipient) Wrap(fileKey []byte) ([]*Stanza, error) {

	h := sha3.NewShake256()
	ct := make([]byte, kyber1024.CiphertextSize)
	h.Reset()
	//ct := publickey.Encrypt(pt:filekey,seed:H(filekey||pk))
	h.Write(fileKey)
	h.Write(r.theirPublicKey)
	seed := make([]byte, kyber1024.KeySeedSize)
	h.Read(seed[:])
	var p kyber1024.PublicKey
	p.Unpack(r.theirPublicKey)

	p.EncryptTo(ct, fileKey[:], seed[:])
	h.Reset()

	//signature := H(fileKey||ct)[:32]
	h.Write(fileKey)
	h.Write(ct)
	sig := make([]byte, 32)
	h.Read(sig[:])

	l := &Stanza{
		Type: "Kyber1024",
		Args: []string{format.EncodeToString(sig)},
		Body: ct,
	}

	return []*Stanza{l}, nil
}

// String returns the Bech32 public key encoding of r.
func (r *Kyber1024Recipient) String() string {
	s, _ := bech32.Encode("age", r.theirPublicKey)
	return s
}

// Kyber1024Identity is the custom age private key, which can decrypt messages
// encrypted to the corresponding Kyber1024Recipient.
type Kyber1024Identity struct {
	ks []byte
}

var _ Identity = &Kyber1024Identity{}

// GenerateKyber1024Identity randomly generates a new Kyber1024Identity.
func GenerateKyber1024Identity() (*Kyber1024Identity, error) {
	var i Kyber1024Identity
	var seed [kyber1024.KeySeedSize]byte
	_, err := io.ReadFull(rand.Reader, seed[:])
	if err != nil {
		return nil, err
	}
	h := sha3.NewShake256()
	h.Write(seed[:])
	h.Read(seed[:])
	i.ks = seed[:]
	return &i, err
}

// ParseKyber1024Identity returns a new Kyber1024Identity from a Kyber1024 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ParseKyber1024Identity(s string) (*Kyber1024Identity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}

	return &Kyber1024Identity{ks: k}, nil
}

func (i *Kyber1024Identity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *Kyber1024Identity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "Kyber1024" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid Kyber1024 recipient block")
	}
	sig, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Kyber1024 sig: %v", err)
	}
	if len(sig[:]) != 32 {
		fmt.Println(len(sig))
		return nil, errors.New("invalid Kyber1024 encap sig size")
	}

	fileKey := make([]byte, kyber1024.PlaintextSize)
	_, sk := kyber1024.NewKeyFromSeed(i.ks[:])
	sk.DecryptTo(fileKey, block.Body)
	h := sha3.NewShake256()
	//signature := H(filekey||ct)
	h.Write(fileKey)
	h.Write(block.Body)
	sig2 := make([]byte, 32)
	h.Read(sig2[:])
	if subtle.ConstantTimeCompare(sig[:], sig2[:]) == 0 {
		return nil, fmt.Errorf("invalid Kyber1024 encap sig")
	}

	return fileKey, nil
}

// Recipient returns the public Kyber1024Recipient value corresponding to i.
func (i *Kyber1024Identity) Recipient() *Kyber1024Recipient {
	var r Kyber1024Recipient
	pk, _ := kyber1024.NewKeyFromSeed(i.ks)
	buf := make([]byte, kyber1024.PublicKeySize)
	pk.Pack(buf)
	r.theirPublicKey = buf
	return &r
}

// String returns the seed of private key
func (i *Kyber1024Identity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.ks)
	return strings.ToUpper(s)
}
