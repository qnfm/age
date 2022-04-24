// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/lukechampine/fastxor"
)

const Kyber1024Mceliece8192128fLabel = "age-encryption.org/v4/Kyber1024Mceliece8192128f"

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
	sch := hybrid.Kyber1024M()
	//sharedKey<-encapsulate(pk) as wrappingKey
	p, err := sch.UnmarshalBinaryPublicKey(r.theirPublicKey)
	if err != nil {
		return nil, err
	}

	ct, ss, err := sch.Encapsulate(p)
	if err != nil {
		return nil, err
	}
	wrappingKey := make([]byte, 32)
	fastxor.Bytes(wrappingKey, ss[:sch.SharedKeySize()/2], ss[sch.SharedKeySize()/2:])
	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}

	//Due to the size of mceliece8192128f.encapsulation,it's more pleasing to put wrappedKey to where ourPublicKey was
	l := &Stanza{
		Type: "Kyber1024Mceliece8192128f",
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
	secretKey, ourPublicKey []byte
}

var _ Identity = &Mceliece8192128fIdentity{}

// GenerateMceliece8192128fIdentity randomly generates a new Mceliece8192128fIdentity.
func GenerateMceliece8192128fIdentity() (*Mceliece8192128fIdentity, error) {
	sch := hybrid.Kyber1024M()
	pub, pri, err := sch.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	pubB, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	privB, err := pri.MarshalBinary()
	if err != nil {
		return nil, err
	}
	i := &Mceliece8192128fIdentity{
		secretKey:    privB,
		ourPublicKey: pubB,
	}
	return i, err
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
	sch := hybrid.Kyber1024M()
	sk, err := sch.UnmarshalBinaryPrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret key: %v", err)
	}
	pk, err := sk.Public().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}
	return &Mceliece8192128fIdentity{secretKey: k, ourPublicKey: pk}, nil
}

func (i *Mceliece8192128fIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *Mceliece8192128fIdentity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "Kyber1024Mceliece8192128f" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid Mceliece8192128f recipient block")
	}
	wrappedKey, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Mceliece8192128f wrappedKey: %v", err)
	}

	sch := hybrid.Kyber1024M()
	sk, err := sch.UnmarshalBinaryPrivateKey(i.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Mceliece8192128f privete key: %v", err)
	}

	ss, err := sch.Decapsulate(sk, block.Body)
	if err != nil {
		return nil, err
	}
	wrappingKey := make([]byte, 32)
	fastxor.Bytes(wrappingKey, ss[:sch.SharedKeySize()/2], ss[sch.SharedKeySize()/2:])

	fileKey, err := aeadDecrypt(wrappingKey, fileKeySize, wrappedKey)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid Mceliece8192128f recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}

	return fileKey, nil
}

// Recipient returns the public Mceliece8192128fRecipient value corresponding to i.
func (i *Mceliece8192128fIdentity) Recipient() *Mceliece8192128fRecipient {
	return &Mceliece8192128fRecipient{theirPublicKey: i.ourPublicKey}
}

// String returns the seed of private key
func (i *Mceliece8192128fIdentity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.secretKey)
	return strings.ToUpper(s)
}
