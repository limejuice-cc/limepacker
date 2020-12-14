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
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHosts(t *testing.T) {
	csr := &CertificateRequest{
		Hosts: []string{"10.1.0.1", "admin@example.com", "https://example.com", "example.com"},
	}

	hosts := csr.parseHosts()

	assert.Len(t, hosts.DNSNames, 1, "dns names should have 1 value")
	assert.Len(t, hosts.EmailAddresses, 1, "email addresses should have 1 value")
	assert.Len(t, hosts.IPAddresses, 1, "ip addresses should have 1 value")
	assert.Len(t, hosts.URIs, 1, "uris should have 1 value")

	assert.Equal(t, "example.com", hosts.DNSNames[0])
	assert.Equal(t, "admin@example.com", hosts.EmailAddresses[0])
	assert.Equal(t, net.ParseIP("10.1.0.1"), hosts.IPAddresses[0])
	uri, _ := url.ParseRequestURI("https://example.com")
	assert.Equal(t, *uri, *hosts.URIs[0])
}
