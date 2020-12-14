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
	"crypto/x509/pkix"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testCSR = `
keyAlgorithm: ecdsa
keySize: 384
commonName: test.example.com
names:
    - C: CA
      ST: QC
      L: Montreal
      O: test org
      OU: test org unit
hosts:
    - example.com
    - admin@example.com
    - localhost
    - 10.1.0.1
`
	testCSRMalformed  = "keyAlgorithm: rsa\n   keySize: 4096"
	testCSRInvalidKey = "keyAlgorithm: badKey"
	testCSRNoNames    = `
keyAlgorithm: ecdsa
keySize: 384	
	`
	testCSREmptyNames = `
keyAlgorithm: ecdsa
keySize: 384
names:
    - C: " "
      ST:
      L: 
      O: 
      OU: 
`
)

func TestParseCSR(t *testing.T) {
	csr, err := ParseCertificateRequest([]byte(testCSR))
	if assert.NoError(t, err) {
		for _, n := range csr.Names {
			assert.False(t, n.Empty())
		}
		assert.Len(t, csr.Hosts, 4)
		assert.Empty(t, csr.SerialNumber)
		key, err := csr.generateKey()
		if assert.NoError(t, err) {
			caExtension, err := generateCAExtension()
			if assert.NoError(t, err) {
				encoded, err := csr.generate(key, []pkix.Extension{}, []pkix.Extension{*caExtension})
				if assert.NoError(t, err) {
					assert.NoError(t, ioutil.WriteFile(filepath.Join("../../testdata/test-csr.pem"), encoded, 0644))
				}
			}
		}
	}

	_, err = ParseCertificateRequest([]byte(testCSRMalformed))
	assert.Error(t, err)

	_, err = ParseCertificateRequest([]byte(testCSRInvalidKey))
	assert.Error(t, err)

	_, err = ParseCertificateRequest([]byte(testCSRNoNames))
	assert.Error(t, err)

	_, err = ParseCertificateRequest([]byte(testCSREmptyNames))
	assert.Error(t, err)

}
