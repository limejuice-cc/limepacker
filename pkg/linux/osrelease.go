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

package linux

import (
	"fmt"
	"strings"

	"github.com/limejuice-cc/limepacker/pkg/utility/keyvalue"
	"github.com/rs/zerolog/log"
)

// Distribution represents the linux distribution
type Distribution int

const (
	noDistributionSet Distribution = iota
	// AlpineLinux refers to alpine linux distributions
	AlpineLinux
	// DebianLinux refers to debian linux distributions
	DebianLinux
	// UbuntuLinux refers to ubuntu linux distributions
	UbuntuLinux
	// FedoraLinux refers to fedora linux distributions
	FedoraLinux
	// GenericLinux refers to a generic linux distribution
	GenericLinux
)

func (d Distribution) String() string {
	switch d {
	case AlpineLinux:
		return "alpine"
	case DebianLinux:
		return "debian"
	case UbuntuLinux:
		return "ubuntu"
	case FedoraLinux:
		return "fedora"
	default:
		return "linux"
	}
}

// ParseDistributionID parses a distribution id
func ParseDistributionID(id string) Distribution {
	switch id {
	case "alpine":
		return AlpineLinux
	case "debian":
		return DebianLinux
	case "ubuntu":
		return UbuntuLinux
	case "fedora":
		return FedoraLinux
	default:
		log.Debug().Msgf("linux distribution %s not recognized", id)
		return GenericLinux
	}
}

// OSRelease represents system information https://www.freedesktop.org/software/systemd/man/os-release.html
type OSRelease struct {
	ID              Distribution
	Name            string
	PrettyName      string
	Version         string
	VersionCodename string
	Extra           map[string]string
}

// ParseOSRelease parses an os-release find
func ParseOSRelease(in string) (*OSRelease, error) {
	pairs, err := keyvalue.ParsePairSlice(in, keyvalue.RemoveOuterQuotes)
	if err != nil {
		return nil, err
	}
	values, err := pairs.ToMap()
	if err != nil {
		return nil, err
	}
	out := &OSRelease{Extra: map[string]string{}}
	for key, value := range values {
		switch key {
		case "ID":
			out.ID = ParseDistributionID(value)
		case "NAME":
			out.Name = value
		case "PRETTY_NAME":
			out.PrettyName = value
		case "VERSION_ID":
			out.Version = value
		case "VERSION_CODENAME":
			out.VersionCodename = value
		default:
			out.Extra[key] = value
		}
	}
	return out, nil
}

func (o *OSRelease) String() string {
	extra := []string{}
	for k, v := range o.Extra {
		extra = append(extra, fmt.Sprintf("%s:%s", k, v))
	}
	return fmt.Sprintf("OSRelease[ID: %s,Name: %s, Pretty Name:%s, Version: %s, Version Codename:%s, Extra: {%s}]",
		o.ID.String(),
		o.Name,
		o.PrettyName,
		o.Version,
		o.VersionCodename,
		strings.Join(extra, ", "))
}
