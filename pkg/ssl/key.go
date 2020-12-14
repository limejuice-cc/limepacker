// Copyright 2020 Limejuice-cc Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/rs/zerolog/log"
)

const (
	minRSAKeySize = 2048
	maxRSAKeySize = 8192
)

// KeyAlgorithm specifies the type of key algorithm to use
type KeyAlgorithm int

const (
	keyAlgorithmNotSet KeyAlgorithm = iota
	// ECDSAKey specifies the ecdsa algorithm
	ECDSAKey
	// RSAKey specifies an RSA key
	RSAKey
)

// ParseKeyAlgorithm parses a key algorithm
func ParseKeyAlgorithm(in string) (KeyAlgorithm, error) {
	switch in {
	case "ecdsa":
		return ECDSAKey, nil
	case "rsa":
		return RSAKey, nil
	default:
		return keyAlgorithmNotSet, fmt.Errorf("unknown key type: %s", in)
	}
}

func (a KeyAlgorithm) String() string {
	switch a {
	case ECDSAKey:
		return "ecdsa"
	case RSAKey:
		return "rsa"
	}
	log.Panic().Msg("unexpected key algorithm")
	return ""
}

// DefaultSize returns the default key size for the specified algorithm
func (a KeyAlgorithm) DefaultSize() int {
	switch a {
	case ECDSAKey:
		return 256
	case RSAKey:
		return 4096
	}
	log.Panic().Msg("unexpected key algorithm")
	return 0
}

// ValidKeySize checks if the supplied key size is valid for the KeyAlgorithm
func (a KeyAlgorithm) ValidKeySize(size int) error {
	switch a {
	case ECDSAKey:
		if !(size == 0 || size == 256 || size == 384 || size == 521) {
			return fmt.Errorf("invalid ecdsa key size %d - key size must be either 256, 384 or 521", size)
		}
		return nil
	case RSAKey:
		if !(size == 0 || (size >= minRSAKeySize && size <= maxRSAKeySize)) {
			return fmt.Errorf("invalid rsa key size %d - key size must be between %d and %d", size, minRSAKeySize, maxRSAKeySize)
		}
		return nil
	}

	log.Panic().Msg("unexpected key algorithm")
	return nil
}

// Key represents a key
type Key interface {
	Algorithm() KeyAlgorithm
	Size() int
	Encoded() []byte
	PrivateKey() crypto.PrivateKey
	PublicKeyAlgorithm() x509.PublicKeyAlgorithm
	PublicKey() crypto.PublicKey
	SignatureAlgorithm() x509.SignatureAlgorithm

	AsReader() io.Reader
}

type baseKey struct {
	algorithm  KeyAlgorithm
	size       int
	encoded    []byte
	privateKey crypto.PrivateKey
}

func (k *baseKey) Algorithm() KeyAlgorithm {
	return k.algorithm
}

func (k *baseKey) Size() int {
	return k.size
}

func (k *baseKey) Encoded() []byte {
	return k.encoded
}

func (k *baseKey) PrivateKey() crypto.PrivateKey {
	return k.privateKey
}

func (k *baseKey) AsReader() io.Reader {
	return bytes.NewReader(k.encoded)
}

func (k *baseKey) PublicKey() crypto.PublicKey {
	switch pub := k.privateKey.(type) {
	case *ecdsa.PrivateKey:
		return pub.Public()
	case *rsa.PrivateKey:
		return pub.Public()
	default:
		log.Panic().Msg("unexpected key algorithm")
		return nil
	}
}

func validateKey(algorithm string, size int) error {
	a, err := ParseKeyAlgorithm(algorithm)
	if err != nil {
		return err
	}
	if err := a.ValidKeySize(size); err != nil {
		return err
	}
	return nil
}

// GenerateKey generates a new key
func GenerateKey(algorithm KeyAlgorithm, size int) (Key, error) {
	if err := algorithm.ValidKeySize(size); err != nil {
		return nil, err
	}

	switch algorithm {
	case ECDSAKey:
		return generateECDSAKey(size)
	case RSAKey:
		return generateRSAKey(size)
	default:
		log.Panic().Msg("unexpected key algorithm")
		return nil, nil
	}
}

type ecdsaKey struct {
	baseKey
}

func (k *ecdsaKey) SignatureAlgorithm() x509.SignatureAlgorithm {
	switch k.size {
	case 256:
		return x509.ECDSAWithSHA256
	case 384:
		return x509.ECDSAWithSHA384
	case 521:
		return x509.ECDSAWithSHA512
	default:
		log.Panic().Msg("unexpected key size")
		return 0
	}
}

func (k *ecdsaKey) PublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	return x509.ECDSA
}

func generateECDSAKey(size int) (*ecdsaKey, error) {
	if size == 0 {
		size = ECDSAKey.DefaultSize()
	}
	var curve elliptic.Curve
	switch size {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		log.Panic().Msgf("unexpected key size %d", size)
		return nil, nil
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	out := &ecdsaKey{}
	out.algorithm = ECDSAKey
	out.size = size
	out.encoded = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	out.privateKey = key

	return out, nil
}

type rsaKey struct {
	baseKey
}

func (k *rsaKey) PublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	return x509.RSA
}

func (k *rsaKey) SignatureAlgorithm() x509.SignatureAlgorithm {
	switch {
	case k.size >= 4096:
		return x509.SHA512WithRSA
	case k.size >= 3072:
		return x509.SHA384WithRSA
	case k.size >= 2048:
		return x509.SHA256WithRSA
	default:
		log.Panic().Msg("unexpected key size")
		return 0
	}
}

func generateRSAKey(size int) (*rsaKey, error) {
	if size == 0 {
		size = RSAKey.DefaultSize()
	}

	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}

	encoded := x509.MarshalPKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}

	out := &rsaKey{}
	out.algorithm = RSAKey
	out.size = size
	out.encoded = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: encoded})
	out.privateKey = key

	return out, nil
}

func getCurveSize(c elliptic.Curve) int {
	if c == elliptic.P256() {
		return 256
	}
	if c == elliptic.P384() {
		return 384
	}
	if c == elliptic.P521() {
		return 521
	}
	return ECDSAKey.DefaultSize()
}

func parsePrivateKey(keyPEM []byte) (Key, error) {
	p, _ := pem.Decode(keyPEM)
	keyDER := p.Bytes

	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(keyDER)
		if err != nil {
			key, err = x509.ParseECPrivateKey(keyDER)
			if err != nil {
				return nil, errors.New("cannot parse private key")
			}
		}
	}

	switch priv := key.(type) {
	case *rsa.PrivateKey:
		out := &rsaKey{}
		out.algorithm = RSAKey
		out.size = priv.Size()
		out.encoded = keyPEM
		out.privateKey = priv
		return out, nil
	case *ecdsa.PrivateKey:
		out := &ecdsaKey{}
		out.algorithm = ECDSAKey
		out.size = getCurveSize(priv.Curve)
		out.encoded = keyPEM
		out.privateKey = priv
		return out, nil
	}

	return nil, errors.New("unknown private key type")
}
