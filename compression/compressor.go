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
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
)

// CompressorOption applies an option to a compressor
type CompressorOption interface {
	Apply(compressor interface{}) error
}

type compressionLevelOption struct {
	level Level
}

// WithCompressionLevel optionally sets the compression level
func WithCompressionLevel(l Level) CompressorOption {
	return &compressionLevelOption{level: l}
}

// Apply applies the CompressionLevelOption
func (o *compressionLevelOption) Apply(compressor interface{}) error {
	switch v := compressor.(type) {
	case zstdCompressor:
		switch o.level {
		case SpeedFastest:
			v.level = zstd.SpeedFastest
		case SpeedDefault:
			v.level = zstd.SpeedDefault
		case SpeedBetterCompression:
			v.level = zstd.SpeedBetterCompression
		case SpeedBestCompression:
			v.level = zstd.SpeedBestCompression
		}
	}
	return nil
}

// Compressor is a generic interface for compressors
type Compressor interface {
	io.WriteCloser
	Algorithm() Algorithm
}

// NewCompressor returns a new compressor
func NewCompressor(w io.Writer, a Algorithm, opts ...CompressorOption) (Compressor, error) {
	switch a {
	case Zstandard:
		return newZstdCompressor(w, opts...)
	}
	log.Panic().Msg("unsupported compression algorithm")
	return nil, nil
}
