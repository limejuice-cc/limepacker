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

package keyvalue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseKV(t *testing.T) {
	var testValues = []struct {
		value   string
		outcome Pair
	}{
		{"key=value", Pair{Key: "key", Value: "value"}},
		{"key  =value", Pair{Key: "key", Value: "value"}},
		{"  key=  value  ", Pair{Key: "key", Value: "value"}},
		{"  key    =  value  ", Pair{Key: "key", Value: "value"}},
		{"key=", Pair{Key: "key", Value: ""}},
		{"key=\"value\"", Pair{Key: "key", Value: "\"value\""}},
	}

	for _, tv := range testValues {
		kv, err := ParsePair(tv.value)
		if assert.NoError(t, err) {
			assert.Equal(t, tv.outcome.Key, kv.Key)
			assert.Equal(t, tv.outcome.Value, kv.Value)
		}
	}

	kv, err := ParsePair("key=\"value\"", RemoveOuterQuotes)
	if assert.NoError(t, err) {
		assert.Equal(t, "key", kv.Key)
		assert.Equal(t, "value", kv.Value)
	}

	kv, err = ParsePair("key='value'", RemoveOuterQuotes)
	if assert.NoError(t, err) {
		assert.Equal(t, "key", kv.Key)
		assert.Equal(t, "value", kv.Value)
	}

	kvSliceIn := `
SHLVL=1
_=/usr/bin/env
HOME_URL="https://example.com/"
; Comment


# Comment
ID=test
`

	kvSlice, err := ParsePairSlice(kvSliceIn, RemoveOuterQuotes)
	if assert.NoError(t, err) {
		kvMap, err := kvSlice.ToMap()
		if assert.NoError(t, err) {
			assert.Equal(t, "1", kvMap["SHLVL"])
			assert.Equal(t, "/usr/bin/env", kvMap["_"])
			assert.Equal(t, "https://example.com/", kvMap["HOME_URL"])
			assert.Equal(t, "test", kvMap["ID"])
		}
	}
}
