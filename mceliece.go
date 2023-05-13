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
	"github.com/cloudflare/circl/kem/mceliece/mceliece8192128f"
	"golang.org/x/crypto/sha3"
)

const Mceliece8192128fLabel = "age-encryption.org/v3/Mceliece8192128f"

// Mceliece8192128fRecipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding Mceliece8192128fIdentity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type Mceliece8192128fRecipient struct {
	theirPublicKey []byte
}

var _ Recipient = &Mceliece8192128fRecipient{}

// ParseMceliece8192128fRecipient returns a new Mceliece8192128fRecipient from a raw string without any encoding
func ParseMceliece8192128fRecipient(s string) (*Mceliece8192128fRecipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}

	return &Mceliece8192128fRecipient{theirPublicKey: k}, nil
}

func (r *Mceliece8192128fRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	//sharedKey<-encapsulate(pk) as wrappingKey
	p, err := mceliece8192128f.Scheme().UnmarshalBinaryPublicKey(r.theirPublicKey)
	if err != nil {
		return nil, err
	}

	ct, wrappingKey, err := p.Scheme().Encapsulate(p)
	if err != nil {
		return nil, err
	}
	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}

	//Due to the size of mceliece8192128f.encapsulation,it's more pleasing to put wrappedKey to where ourPublicKey was
	l := &Stanza{
		Type: "Mceliece8192128f",
		Args: []string{format.EncodeToString(wrappedKey)},
		Body: ct,
	}

	return []*Stanza{l}, nil
}

// String returns the Bech32 public key encoding of r.
func (r *Mceliece8192128fRecipient) String() string {
	s, _ := bech32.Encode("age", r.theirPublicKey)
	return s
}

// Mceliece8192128fIdentity is the key seed bind to a certain mceliece8192128f.(pk,sk) key pair, which can decapsulate messages
// encrypted to the corresponding Mceliece8192128fRecipient.
type Mceliece8192128fIdentity struct {
	ks []byte
}

var _ Identity = &Mceliece8192128fIdentity{}

// GenerateMceliece8192128fIdentity randomly generates a new Mceliece8192128fIdentity.
func GenerateMceliece8192128fIdentity() (*Mceliece8192128fIdentity, error) {
	var i Mceliece8192128fIdentity
	seed := make([]byte, mceliece8192128f.Scheme().SeedSize())
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

// ParseMceliece8192128fIdentity returns a new Mceliece8192128fIdentity from a Mceliece8192128f private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ParseMceliece8192128fIdentity(s string) (*Mceliece8192128fIdentity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}

	return &Mceliece8192128fIdentity{ks: k}, nil
}

func (i *Mceliece8192128fIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *Mceliece8192128fIdentity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "Mceliece8192128f" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid Mceliece8192128f recipient block")
	}
	wrappedKey, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Mceliece8192128f wrappedKey: %v", err)
	}

	_, sk := mceliece8192128f.Scheme().DeriveKeyPair(i.ks[:])
	wrappingkey, err := sk.Scheme().Decapsulate(sk, block.Body)
	if err != nil {
		return nil, err
	}
	fileKey, err := aeadDecrypt(wrappingkey, fileKeySize, wrappedKey)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid Mceliece8192128f recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}

	return fileKey, nil
}

// Recipient returns the public Mceliece8192128fRecipient value corresponding to i.
func (i *Mceliece8192128fIdentity) Recipient() *Mceliece8192128fRecipient {
	var r Mceliece8192128fRecipient
	pk, _ := mceliece8192128f.Scheme().DeriveKeyPair(i.ks)
	var err error
	r.theirPublicKey, err = pk.MarshalBinary()
	if err != nil {
		return nil
	}
	return &r
}

// String returns the seed of private key
func (i *Mceliece8192128fIdentity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.ks)
	return strings.ToUpper(s)
}
