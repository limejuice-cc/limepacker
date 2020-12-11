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

package build

import (
	"fmt"
)

var (
	// BuildDate is set automatically on build.
	BuildDate = "NA"
	// MajorVersion is set automatically on build.
	MajorVersion = "0"
	// MinorVersion is set automatically on build.
	MinorVersion = "0"
	// PatchVersion is set automatically on build.
	PatchVersion = "0"
)

// Version returns the current version as a formatted string.
func Version() string {
	return fmt.Sprintf("v%s.%s.%s", MajorVersion, MinorVersion, PatchVersion)
}
