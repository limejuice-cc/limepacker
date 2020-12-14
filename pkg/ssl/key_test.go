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

func TestKeyFunctions(t *testing.T) {
	ecdsaKeySizes := []int{0, 256, 384, 521}
	a, err := ParseKeyAlgorithm("ecdsa")
	if assert.NoError(t, err) {
		assert.Equal(t, ECDSAKey, a)
		for _, keySize := range ecdsaKeySizes {
			key, err := GenerateKey(a, keySize)
			if assert.NoError(t, err) {
				assert.Equal(t, ECDSAKey, key.Algorithm())
				if keySize == 0 {
					assert.Equal(t, ECDSAKey.DefaultSize(), key.Size())
				} else {
					assert.Equal(t, keySize, key.Size())
				}
				assert.NotEmpty(t, key.Encoded())
				assert.NotNil(t, key.PrivateKey())
			}
		}
	}

	a, err = ParseKeyAlgorithm("rsa")
	if assert.NoError(t, err) {
		assert.Equal(t, RSAKey, a)
		key, err := GenerateKey(a, 0)
		if assert.NoError(t, err) {
			assert.Equal(t, RSAKey, key.Algorithm())
			assert.Equal(t, RSAKey.DefaultSize(), key.Size())
			assert.NotEmpty(t, key.Encoded())
			assert.NotNil(t, key.PrivateKey())
		}
	}

	assert.Panics(t, func() { _ = keyAlgorithmNotSet.String() })
	assert.Panics(t, func() { keyAlgorithmNotSet.DefaultSize() })
	assert.Panics(t, func() { keyAlgorithmNotSet.ValidKeySize(333) })

	assert.Panics(t, func() { GenerateKey(keyAlgorithmNotSet, 0) })

	assert.Panics(t, func() { generateECDSAKey(222) })

	assert.Error(t, ECDSAKey.ValidKeySize(5))
	assert.Error(t, RSAKey.ValidKeySize(minRSAKeySize-1))
	assert.Error(t, RSAKey.ValidKeySize(maxRSAKeySize+1))

	assert.Error(t, validateKey("ecdsa", 222))
	assert.Error(t, validateKey("rsa", 222))
	assert.Error(t, validateKey("ddd", 222))

	_, err = GenerateKey(RSAKey, 5)
	assert.Error(t, err)

	assert.Equal(t, "ecdsa", ECDSAKey.String())
	assert.Equal(t, "rsa", RSAKey.String())

	key, err := GenerateKey(RSAKey, 0)
	if assert.NoError(t, err) {
		assert.NoError(t, ioutil.WriteFile(filepath.Join("../../testdata", "test-rsa-key.pem"), key.Encoded(), 0644))
	}

	key, err = GenerateKey(ECDSAKey, 0)
	if assert.NoError(t, err) {
		assert.NoError(t, ioutil.WriteFile(filepath.Join("../../testdata", "test-ec-key.pem"), key.Encoded(), 0644))
	}
}
