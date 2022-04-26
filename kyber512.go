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
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"golang.org/x/crypto/sha3"
)

const KyberLabel = "age-encryption.org/v3/Kyber512"

// Kyber512Recipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding Kyber512Identity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type Kyber512Recipient struct {
	theirPublicKey []byte
}

var _ Recipient = &Kyber512Recipient{}

// ParseKyber512Recipient returns a new Kyber512Recipient from a raw string without any encoding
func ParseKyber512Recipient(s string) (*Kyber512Recipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}

	return &Kyber512Recipient{theirPublicKey: k}, nil
}

func (r *Kyber512Recipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	//sharedKey<-encapsulate(pk) as wrappingKey
	var p kyber512.PublicKey
	p.Unpack(r.theirPublicKey)
	ct := make([]byte, kyber512.CiphertextSize)
	wrappingKey := make([]byte, kyber512.SharedKeySize)
	p.EncapsulateTo(ct, wrappingKey, nil)

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}

	//Due to the size of kyber.encapsulation,it's more pleasing to put wrappedKey to where ourPublicKey was
	l := &Stanza{
		Type: "Kyber512",
		Args: []string{format.EncodeToString(wrappedKey)},
		Body: ct,
	}

	return []*Stanza{l}, nil
}

// String returns the Bech32 public key encoding of r.
func (r *Kyber512Recipient) String() string {
	s, _ := bech32.Encode("age", r.theirPublicKey)
	return s
}

// Kyber512Identity is the key seed bind to a certain kyber512.(pk,sk) key pair, which can decapsulate messages
// encrypted to the corresponding Kyber512Recipient.
type Kyber512Identity struct {
	ks []byte
}

var _ Identity = &Kyber512Identity{}

// GenerateKyber512Identity randomly generates a new Kyber512Identity.
func GenerateKyber512Identity() (*Kyber512Identity, error) {
	var i Kyber512Identity
	var seed [kyber512.KeySeedSize]byte
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

// ParseKyber512Identity returns a new Kyber512Identity from a Kyber512 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ParseKyber512Identity(s string) (*Kyber512Identity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}

	return &Kyber512Identity{ks: k}, nil
}

func (i *Kyber512Identity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *Kyber512Identity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "Kyber512" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid Kyber512 recipient block")
	}
	wrappedKey, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Kyber512 wrappedKey: %v", err)
	}

	wrappingkey := make([]byte, kyber512.SharedKeySize)
	_, sk := kyber512.NewKeyFromSeed(i.ks[:])
	sk.DecapsulateTo(wrappingkey, block.Body)
	fileKey, err := aeadDecrypt(wrappingkey, fileKeySize, wrappedKey)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid Kyber512 recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}

	return fileKey, nil
}

// Recipient returns the public Kyber512Recipient value corresponding to i.
func (i *Kyber512Identity) Recipient() *Kyber512Recipient {
	var r Kyber512Recipient
	pk, _ := kyber512.NewKeyFromSeed(i.ks)
	buf := make([]byte, kyber512.PublicKeySize)
	pk.Pack(buf)
	r.theirPublicKey = buf
	return &r
}

// String returns the seed of private key
func (i *Kyber512Identity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.ks)
	return strings.ToUpper(s)
}
