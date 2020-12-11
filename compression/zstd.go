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
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

type zstdCompressor struct {
	encoder *zstd.Encoder
	level   zstd.EncoderLevel
}

func (z *zstdCompressor) Algorithm() Algorithm {
	return Zstandard
}

func (z *zstdCompressor) Write(p []byte) (int, error) {
	if z.encoder == nil {
		return 0, errors.New("compressor is not open")
	}
	return z.encoder.Write(p)
}

func (z *zstdCompressor) Close() error {
	if z.encoder == nil {
		return nil
	}
	defer func() {
		z.encoder = nil
	}()
	return z.encoder.Close()
}

func newZstdCompressor(w io.Writer, opts ...CompressorOption) (Compressor, error) {
	c := &zstdCompressor{
		level: zstd.SpeedBestCompression,
	}

	for _, opt := range opts {
		if err := opt.Apply(c); err != nil {
			return nil, err
		}
	}

	enc, err := zstd.NewWriter(w, zstd.WithEncoderLevel(c.level))
	if err != nil {
		return nil, err
	}
	c.encoder = enc

	return c, nil
}

type zstdDecompressor struct {
	decoder *zstd.Decoder
}

func (z *zstdDecompressor) Read(p []byte) (int, error) {
	if z.decoder == nil {
		return 0, errors.New("decompressor is not open")
	}
	return z.decoder.Read(p)
}

func (z *zstdDecompressor) Close() error {
	if z.decoder == nil {
		return nil
	}
	defer func() {
		z.decoder = nil
	}()
	z.decoder.Close()
	return nil
}

func (z *zstdDecompressor) Algorithm() Algorithm {
	return Zstandard
}

func newZstdDecompressor(r io.Reader, opts ...DecompressorOption) (Decompressor, error) {
	dec, err := zstd.NewReader(r)
	if err != nil {
		return nil, err
	}
	return &zstdDecompressor{decoder: dec}, nil
}

const (
	zstdMagic          uint32 = 0xFD2FB528
	zstdMagicSkipStart uint32 = 0x184D2A50
	zstdMagicSkipMask  uint32 = 0xFFFFFFF0
)

func autoDetectZstd(r io.ReadSeeker) (bool, error) {
	signature := make([]byte, 4)
	if l, err := r.Read(signature); err != nil || l < 4 {
		return false, err
	}
	if _, err := r.Seek(-4, os.SEEK_CUR); err != nil {
		return false, err
	}
	prefix := binary.LittleEndian.Uint32(signature)
	if prefix == zstdMagic || (prefix&zstdMagicSkipMask) == zstdMagicSkipStart {
		return true, nil
	}
	return false, nil
}
