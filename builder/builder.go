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

package builder

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/limejuice-cc/limepacker/manifest"
)

// File represents a built file
type File interface {
	Name() string
	User() string
	Group() string
	Body() []byte
	Size() int
	Mode() os.FileMode
	Type() manifest.FileType
	String() string
}

type baseFile struct {
	name     string
	user     string
	group    string
	body     []byte
	mode     os.FileMode
	fileType manifest.FileType
}

func (f *baseFile) Name() string {
	return f.name
}

func (f *baseFile) User() string {
	return f.user
}
func (f *baseFile) Group() string {
	return f.group
}

func (f *baseFile) Body() []byte {
	return f.body
}

func (f *baseFile) Size() int {
	return len(f.body)
}

func (f *baseFile) Mode() os.FileMode {
	return f.mode
}

func (f *baseFile) Type() manifest.FileType {
	return f.fileType
}

func (f *baseFile) String() string {
	return fmt.Sprintf("File: %s", f.name)
}

func newFile(r io.Reader, name, user, group string, mode os.FileMode, fileType manifest.FileType) (File, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return &baseFile{
		name:     name,
		user:     user,
		group:    group,
		body:     body,
		mode:     mode,
		fileType: fileType,
	}, nil
}

// Results represents the results of a build operation
type Results interface {
	Files() []File
}

type baseResults struct {
	files []File
}

func (r *baseResults) Files() []File {
	return r.files
}

func newResults() *baseResults {
	return &baseResults{
		files: []File{},
	}
}

func (r *baseResults) String() string {
	var sb strings.Builder
	sb.WriteString("Results: ")
	for _, f := range r.files {
		fmt.Fprintln(&sb, f.String())
	}
	return sb.String()
}

// Build is a generic interface to build package contents
type Build interface {
	Architecture() string
	SetArchitecture(architecture string) error
	OS() string
	SetOS(os string) error
	Run() (Results, error)
}

type baseBuilder struct {
	architecture string
	os           string
	variant      string
}

func (b *baseBuilder) Architecture() string {
	if b.architecture == "" {
		return "amd64"
	}
	return b.architecture
}

func (b *baseBuilder) SetArchitecture(architecture string) error {
	b.architecture = architecture
	return nil
}

func (b *baseBuilder) OS() string {
	if b.os == "" {
		return "linux"
	}
	return b.os
}

func (b *baseBuilder) SetOS(os string) error {
	b.os = os
	return nil
}

func (b *baseBuilder) Variant() string {
	return b.variant
}

func (b *baseBuilder) SetVariant(variant string) error {
	b.variant = variant
	return nil
}
