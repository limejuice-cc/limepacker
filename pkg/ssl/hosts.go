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
	"net/mail"
	"net/url"
)

type certificateHosts struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

func (csr *CertificateRequest) parseHosts() *certificateHosts {
	out := &certificateHosts{
		DNSNames:       []string{},
		EmailAddresses: []string{},
		IPAddresses:    []net.IP{},
		URIs:           []*url.URL{},
	}
	for _, host := range csr.Hosts {
		if ip := net.ParseIP(host); ip != nil {
			out.IPAddresses = append(out.IPAddresses, ip)
			continue
		}

		if email, err := mail.ParseAddress(host); err == nil && email != nil {
			out.EmailAddresses = append(out.EmailAddresses, email.Address)
			continue
		}

		if uri, err := url.ParseRequestURI(host); err == nil && uri != nil {
			out.URIs = append(out.URIs, uri)
			continue
		}

		out.DNSNames = append(out.DNSNames, host)
	}

	return out
}
