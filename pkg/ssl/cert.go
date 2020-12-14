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
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"time"
)

const (
	// DefaultCertificateExpiration is the default certificate expiration (10 yrs)
	DefaultCertificateExpiration = 10 * 8760 * time.Hour
)

var keyUsage = map[string]x509.KeyUsage{
	"signing":            x509.KeyUsageDigitalSignature,
	"digital signature":  x509.KeyUsageDigitalSignature,
	"content commitment": x509.KeyUsageContentCommitment,
	"key encipherment":   x509.KeyUsageKeyEncipherment,
	"key agreement":      x509.KeyUsageKeyAgreement,
	"data encipherment":  x509.KeyUsageDataEncipherment,
	"cert sign":          x509.KeyUsageCertSign,
	"crl sign":           x509.KeyUsageCRLSign,
	"encipher only":      x509.KeyUsageEncipherOnly,
	"decipher only":      x509.KeyUsageDecipherOnly,
}

var extKeyUsage = map[string]x509.ExtKeyUsage{
	"any":              x509.ExtKeyUsageAny,
	"server auth":      x509.ExtKeyUsageServerAuth,
	"client auth":      x509.ExtKeyUsageClientAuth,
	"code signing":     x509.ExtKeyUsageCodeSigning,
	"email protection": x509.ExtKeyUsageEmailProtection,
	"s/mime":           x509.ExtKeyUsageEmailProtection,
	"ipsec end system": x509.ExtKeyUsageIPSECEndSystem,
	"ipsec tunnel":     x509.ExtKeyUsageIPSECTunnel,
	"ipsec user":       x509.ExtKeyUsageIPSECUser,
	"timestamping":     x509.ExtKeyUsageTimeStamping,
	"ocsp signing":     x509.ExtKeyUsageOCSPSigning,
	"microsoft sgc":    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"netscape sgc":     x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

func sortUsages(usages []string) (x509.KeyUsage, []x509.ExtKeyUsage) {
	var ku x509.KeyUsage
	eku := []x509.ExtKeyUsage{}
	for _, u := range usages {
		if kuse, ok := keyUsage[u]; ok {
			ku |= kuse
		} else if ekuse, ok := extKeyUsage[u]; ok {
			eku = append(eku, ekuse)
		}
	}
	return ku, eku
}

func generateCertificateTemplate(csrData []byte, expires time.Duration, usage []string, isCA bool) (*x509.Certificate, Key, error) {
	csr, err := ParseCertificateRequest(csrData)
	if err != nil {
		return nil, nil, err
	}

	if expires.Seconds() == 0 {
		expires = DefaultCertificateExpiration
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, nil, err
	}

	key, err := csr.generateKey()
	if err != nil {
		return nil, nil, err
	}

	hosts := csr.parseHosts()
	ku, eku := sortUsages(usage)
	if ku == 0 && len(eku) == 0 {
		return nil, nil, errors.New("no key usage(s) specified")
	}

	now := time.Now()
	return &x509.Certificate{
		Subject:               *csr.subject(),
		PublicKey:             key.PublicKey(),
		PublicKeyAlgorithm:    key.PublicKeyAlgorithm(),
		SignatureAlgorithm:    key.SignatureAlgorithm(),
		IPAddresses:           hosts.IPAddresses,
		EmailAddresses:        hosts.EmailAddresses,
		URIs:                  hosts.URIs,
		DNSNames:              hosts.DNSNames,
		SerialNumber:          serialNumber,
		NotBefore:             now.Add(-5 * time.Minute).UTC(),
		NotAfter:              now.Add(expires).UTC(),
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}, key, nil
}

// GenerateCA generates a self signed certificate authority pem encoded certificate
func GenerateCA(csrData []byte, expires time.Duration) ([]byte, []byte, error) {
	template, key, err := generateCertificateTemplate(csrData, expires, []string{"cert sign", "crl sign"}, true)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey(), key.PrivateKey())
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), key.Encoded(), nil
}

// Generate generates a new certificate
func Generate(csrData, ca, caKey []byte, expires time.Duration, usage []string) ([]byte, []byte, error) {
	template, key, err := generateCertificateTemplate(csrData, expires, usage, false)
	if err != nil {
		return nil, nil, err
	}

	p, _ := pem.Decode(ca)
	caCert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, nil, err
	}

	caPrivateKey, err := parsePrivateKey(caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, key.PublicKey(), caPrivateKey.PrivateKey())
	if err != nil {
		return nil, nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})

	return encoded, key.Encoded(), nil
}
