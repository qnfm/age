// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"github.com/cloudflare/circl/kem/hybrid"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

const Kyber1024X448Label = "age-encryption.org/v3/Kyber1024X448"

// Kyber1024X448Recipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding Kyber1024X448Identity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type Kyber1024X448Recipient struct {
	theirPublicKey []byte
}

var _ Recipient = &Kyber1024X448Recipient{}

// ParseKyber1024X448Recipient returns a new Kyber1024X448Recipient from a raw string without any encoding
func ParseKyber1024X448Recipient(s string) (*Kyber1024X448Recipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}

	return &Kyber1024X448Recipient{theirPublicKey: k}, nil
}

func (r *Kyber1024X448Recipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	p, err := hybrid.Kyber1024X448().UnmarshalBinaryPublicKey(r.theirPublicKey)
	if err != nil {
		return nil, err
	}
	ct, wrappingKey, err := hybrid.Kyber1024X448().Encapsulate(p)
	if err != nil {
		return nil, err
	}
	h := sha3.NewShake256()
	h.Write(wrappingKey)
	wrappingKey = make([]byte, chacha20poly1305.KeySize)
	h.Read(wrappingKey)
	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}

	//Due to the size of kyber.encapsulation,it's more pleasing to put wrappedKey to where ourPublicKey was
	l := &Stanza{
		Type: "Kyber1024X448",
		Args: []string{format.EncodeToString(wrappedKey)},
		Body: ct,
	}

	return []*Stanza{l}, nil
}

// String returns the Bech32 public key encoding of r.
func (r *Kyber1024X448Recipient) String() string {
	s, _ := bech32.Encode("age", r.theirPublicKey)
	return s
}

// Kyber1024X448Identity is the key seed bind to a certain Kyber1024X448.(pk,sk) key pair, which can decapsulate messages
// encrypted to the corresponding Kyber1024X448Recipient.
type Kyber1024X448Identity struct {
	ks []byte
}

var _ Identity = &Kyber1024X448Identity{}

// GenerateKyber1024X448Identity randomly generates a new Kyber1024X448Identity.
func GenerateKyber1024X448Identity() (*Kyber1024X448Identity, error) {
	var i Kyber1024X448Identity
	seed := make([]byte, hybrid.Kyber1024X448().SeedSize())
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

// ParseKyber1024X448Identity returns a new Kyber1024X448Identity from a Kyber1024X448 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ParseKyber1024X448Identity(s string) (*Kyber1024X448Identity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}

	return &Kyber1024X448Identity{ks: k}, nil
}

func (i *Kyber1024X448Identity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *Kyber1024X448Identity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "Kyber1024X448" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid Kyber1024X448 recipient block")
	}
	wrappedKey, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Kyber1024X448 wrappedKey: %v", err)
	}

	_, sk := hybrid.Kyber1024X448().DeriveKeyPair(i.ks)

	wrappingKey, err := sk.Scheme().Decapsulate(sk, block.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	h := sha3.NewShake256()
	h.Write(wrappingKey)
	wrappingKey = make([]byte, chacha20poly1305.KeySize)
	h.Read(wrappingKey)
	fileKey, err := aeadDecrypt(wrappingKey, fileKeySize, wrappedKey)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid Kyber1024X448 recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}

	return fileKey, nil
}

// Recipient returns the public Kyber1024X448Recipient value corresponding to i.
func (i *Kyber1024X448Identity) Recipient() *Kyber1024X448Recipient {
	r := &Kyber1024X448Recipient{}
	pk, _ := hybrid.Kyber1024X448().DeriveKeyPair(i.ks)
	buf, err := pk.MarshalBinary()
	if err != nil {
		return nil
	}
	r.theirPublicKey = buf
	return r
}

// String returns the seed of private key
func (i *Kyber1024X448Identity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.ks)
	return strings.ToUpper(s)
}
