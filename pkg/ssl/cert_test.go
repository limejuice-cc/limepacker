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
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCA(t *testing.T) {
	cert, key, err := GenerateCA([]byte(testCSR), DefaultCertificateExpiration)
	if assert.NoError(t, err) {
		assert.NoError(t, ioutil.WriteFile(filepath.Join("../../testdata", "test-ca.pem"), cert, 0644))
		assert.NoError(t, ioutil.WriteFile(filepath.Join("../../testdata", "test-ca-key.pem"), key, 0644))
	}
}

func TestGenerate(t *testing.T) {
	caCert, caKey, err := GenerateCA([]byte(testCSR), DefaultCertificateExpiration)
	if assert.NoError(t, err) {
		cert, key, err := Generate([]byte(testCSR), caCert, caKey, DefaultCertificateExpiration, []string{"signing", "key encipherment", "server auth", "client auth"})
		if assert.NoError(t, err) {
			assert.NoError(t, ioutil.WriteFile(filepath.Join("../../testdata", "test-cert.pem"), cert, 0644))
			assert.NoError(t, ioutil.WriteFile(filepath.Join("../../testdata", "test-cert-key.pem"), key, 0644))
		}
	}
}
