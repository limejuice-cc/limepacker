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
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	osReleaseTest = `
NAME="Ubuntu"
VERSION="20.04.1 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.1 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal	
	`
)

func TestParseOSRelease(t *testing.T) {
	v, err := ParseOSRelease(osReleaseTest)
	if assert.NoError(t, err) {
		assert.Equal(t, UbuntuLinux, v.ID)
		assert.Equal(t, "Ubuntu", v.Name)
		assert.Equal(t, "Ubuntu 20.04.1 LTS", v.PrettyName)
		assert.Equal(t, "20.04", v.Version)
		assert.Equal(t, "focal", v.VersionCodename)
		assert.Equal(t, "https://www.ubuntu.com/", v.Extra["HOME_URL"])
	}
}
