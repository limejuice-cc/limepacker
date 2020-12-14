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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"

	"gopkg.in/yaml.v2"
)

// CertificateName contains subject fields
type CertificateName struct {
	C            string `yaml:"C"`                      // Country
	ST           string `yaml:"ST"`                     // Province
	L            string `yaml:"L"`                      // Locality
	O            string `yaml:"O"`                      // OrganizationName
	OU           string `yaml:"OU,omitempty"`           // OrganizationalUnitName
	SerialNumber string `yaml:"serialNumber,omitempty"` // SerialNumber
}

func (n *CertificateName) trim() {
	n.C = strings.TrimSpace(n.C)
	n.ST = strings.TrimSpace(n.ST)
	n.L = strings.TrimSpace(n.L)
	n.O = strings.TrimSpace(n.O)
	n.OU = strings.TrimSpace(n.OU)
	n.SerialNumber = strings.TrimSpace(n.SerialNumber)
}

// Empty returns true if the certificate name is empty
func (n *CertificateName) Empty() bool {
	return (len(n.C) + len(n.ST) + len(n.L) + len(n.O) + len(n.OU)) == 0
}

// CertificateRequest represents a certificate request
type CertificateRequest struct {
	Algorithm    string            `yaml:"keyAlgorithm"`           // Algorithm
	Size         int               `yaml:"keySize,omitempty"`      // Size
	CommonName   string            `yaml:"commonName"`             // CommonName
	Names        []CertificateName `yaml:"names,omitempty"`        // Names
	Hosts        []string          `yaml:"hosts,omitempty"`        // Hosts
	SerialNumber string            `yaml:"serialNumber,omitempty"` // SerialNumber
}

func (csr *CertificateRequest) subject() *pkix.Name {
	subject := &pkix.Name{}
	subject.CommonName = csr.CommonName

	for _, n := range csr.Names {
		if len(n.C) > 0 {
			subject.Country = append(subject.Country, n.C)
		}

		if len(n.ST) > 0 {
			subject.Province = append(subject.Province, n.ST)
		}

		if len(n.L) > 0 {
			subject.Province = append(subject.Locality, n.L)
		}

		if len(n.O) > 0 {
			subject.Organization = append(subject.Organization, n.O)
		}

		if len(n.OU) > 0 {
			subject.OrganizationalUnit = append(subject.OrganizationalUnit, n.OU)
		}
	}

	subject.SerialNumber = csr.SerialNumber
	return subject
}

// ParseCertificateRequest parses a yaml encoded certificate request
func ParseCertificateRequest(in []byte) (*CertificateRequest, error) {
	var csr CertificateRequest
	if err := yaml.Unmarshal(in, &csr); err != nil {
		return nil, err
	}

	if err := validateKey(csr.Algorithm, csr.Size); err != nil {
		return nil, err
	}

	csr.CommonName = strings.TrimSpace(csr.CommonName)
	csr.SerialNumber = strings.TrimSpace(csr.SerialNumber)

	names := []CertificateName{}
	for i := range csr.Names {
		csr.Names[i].trim()
		if csr.Names[i].Empty() {
			continue
		}
		names = append(names, csr.Names[i])
	}
	csr.Names = names

	for i := range csr.Hosts {
		csr.Hosts[i] = strings.TrimSpace(csr.Hosts[i])
	}

	if csr.CommonName == "" && len(csr.Names) == 0 {
		return nil, errors.New("no subject information provided")
	}

	return &csr, nil
}

func (csr *CertificateRequest) generateKey() (Key, error) {
	algorithm, err := ParseKeyAlgorithm(csr.Algorithm)
	if err != nil {
		return nil, err
	}
	return GenerateKey(algorithm, csr.Size)
}

func (csr *CertificateRequest) generate(key Key, extensions []pkix.Extension, ExtraExtensions []pkix.Extension) ([]byte, error) {
	hosts := csr.parseHosts()
	template := &x509.CertificateRequest{
		Subject:            *csr.subject(),
		SignatureAlgorithm: key.SignatureAlgorithm(),
		IPAddresses:        hosts.IPAddresses,
		EmailAddresses:     hosts.EmailAddresses,
		URIs:               hosts.URIs,
		DNSNames:           hosts.DNSNames,
		Extensions:         extensions,
		ExtraExtensions:    ExtraExtensions,
	}

	out, err := x509.CreateCertificateRequest(rand.Reader, template, key.PrivateKey())
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: out}), nil
}

func generateCAExtension() (*pkix.Extension, error) {
	type BasicConstraints struct {
		IsCA bool `asn1:"optional"`
	}
	val, err := asn1.Marshal(BasicConstraints{true})
	if err != nil {
		return nil, err
	}
	return &pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Value:    val,
		Critical: true,
	}, nil
}
