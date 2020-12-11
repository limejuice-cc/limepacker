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
	"bufio"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Pair represents a simple pair of a key and value
type Pair struct {
	Key   string
	Value string
}

func (kv *Pair) String() string {
	return fmt.Sprintf("%s=%s", kv.Key, kv.Value)
}

var (
	keyValueRegex = regexp.MustCompile(`^([^=]+)=(.*)$`)
)

// TransformPair applies a transformation to a KeyValuePair
type TransformPair func(kv *Pair) error

// RemoveOuterQuotes removes outer quotes on a value
func RemoveOuterQuotes(kv *Pair) error {
	if len(kv.Value) > 2 && strings.HasPrefix(kv.Value, "\"") && strings.HasSuffix(kv.Value, "\"") {
		kv.Value = kv.Value[1:(len(kv.Value) - 1)]
		return nil
	}
	if len(kv.Value) > 2 && strings.HasPrefix(kv.Value, "'") && strings.HasSuffix(kv.Value, "'") {
		kv.Value = kv.Value[1:(len(kv.Value) - 1)]
		return nil
	}
	return nil
}

// KeyToUpper transforms the key to uppercase
func KeyToUpper(kv *Pair) error {
	kv.Key = strings.ToUpper(kv.Key)
	return nil
}

// PairSlice represents a slice of KeyValuePair
type PairSlice []*Pair

func (s PairSlice) String() string {
	pairs := make([]string, len(s))
	for _, p := range s {
		pairs = append(pairs, p.String())
	}
	return strings.Join(pairs, ", ")
}

// ToMap converts a PairSlice to a KeyValuePairMap returning an error if there are duplicate keys
func (s PairSlice) ToMap() (PairMap, error) {
	out := make(PairMap, len(s))
	for _, kv := range s {
		if _, ok := out[kv.Key]; ok {
			return nil, fmt.Errorf("duplicate keys %s", kv.Key)
		}
		out[kv.Key] = kv.Value
	}
	return out, nil
}

// PairMap represents a PairSlice transformed as a map[string]string
type PairMap map[string]string

// ParsePair parses a Pair delimited as "key=value"
func ParsePair(value string, transform ...TransformPair) (*Pair, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("value cannot be empty")
	}
	if groups := keyValueRegex.FindStringSubmatch(value); groups != nil {
		kv := &Pair{
			Key:   strings.TrimSpace(groups[1]),
			Value: strings.TrimSpace(groups[2]),
		}
		for _, t := range transform {
			if err := t(kv); err != nil {
				return nil, err
			}
		}
		return kv, nil
	}

	return nil, errors.New("invalid syntax")
}

// ParsePairSlice parses a list of newline delimited key value pairs
func ParsePairSlice(in string, transform ...TransformPair) (PairSlice, error) {
	out := PairSlice{}
	scanner := bufio.NewScanner(strings.NewReader(in))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if kv, err := ParsePair(line, transform...); err == nil {
			out = append(out, kv)
		} else {
			return nil, err
		}
	}
	return out, nil
}
