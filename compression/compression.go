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

package compression

import (
	"errors"
	"io"

	"github.com/rs/zerolog/log"
)

// Algorithm is the compression algorithm to use.
type Algorithm int

func (c Algorithm) String() string {
	switch c {
	case Zstandard:
		return "Zstandard"
	}
	log.Panic().Msg("invalid compression algorithm")
	return ""
}

// Extension returns the comprssion algorithm's file extension
func (c Algorithm) Extension() string {
	switch c {
	case Zstandard:
		return "zst"
	}
	log.Panic().Msg("invalid compression algorithm")
	return ""
}

// MimeType returns the compression algorithm's mime type
func (c Algorithm) MimeType() string {
	switch c {
	case Zstandard:
		return "application/zstd"
	}
	log.Panic().Msg("invalid compression algorithm")
	return ""
}

const (
	compressionAlgorithmNotSet Algorithm = iota
	// Zstandard uses the zstd algorithm
	Zstandard
	// DefaultAlgorithm is the default compression algorithm to use
	DefaultAlgorithm = Zstandard
)

// Level defines the level of compression
type Level int

const (
	speedNotSet Level = iota
	// SpeedFastest will choose the fastest reasonable compression.
	SpeedFastest
	// SpeedDefault is the default "pretty fast" compression option.
	SpeedDefault
	// SpeedBetterCompression will yield better compression than the default.
	SpeedBetterCompression
	// SpeedBestCompression will choose the best available compression option.
	SpeedBestCompression
)

// AutoDetect attempts to detect the compression algorithm used
func AutoDetect(r io.ReadSeeker) (Algorithm, error) {
	if ok, err := autoDetectZstd(r); ok {
		return Zstandard, nil
	} else if err != nil {
		log.Panic().Msg("unexpected error while autodetecting compression algorithm")
		return compressionAlgorithmNotSet, errors.New("system error")
	}
	return compressionAlgorithmNotSet, errors.New("cannot autodetect algorithm")
}
