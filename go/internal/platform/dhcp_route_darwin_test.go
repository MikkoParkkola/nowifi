//go:build darwin

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package platform

import "testing"

func TestParseClasslessStaticRoutes_Darwin(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []DHCPRoute
	}{
		{
			name: "standard ipconfig format",
			in: "op = BOOTREPLY\n" +
				"classless_static_route (ip_mult): {10.0.0.0/8, 192.168.1.1}, {0.0.0.0/0, 192.168.1.1}\n" +
				"server_identifier (ip): 192.168.1.1\n",
			want: []DHCPRoute{
				{CIDR: "10.0.0.0/8", Gateway: "192.168.1.1"},
				{CIDR: "0.0.0.0/0", Gateway: "192.168.1.1"},
			},
		},
		{
			name: "option_121 alias",
			in:   "option_121 (dhcp_option): {172.16.0.0/12, 10.0.0.1}\n",
			want: []DHCPRoute{{CIDR: "172.16.0.0/12", Gateway: "10.0.0.1"}},
		},
		{
			name: "no option 121",
			in:   "op = BOOTREPLY\nserver_identifier (ip): 192.168.1.1\n",
			want: nil,
		},
		{
			name: "single route only",
			in:   "classless_static_route (ip_mult): {8.8.8.8/32, 10.0.0.1}\n",
			want: []DHCPRoute{{CIDR: "8.8.8.8/32", Gateway: "10.0.0.1"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseClasslessStaticRoutes(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (got %v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("[%d] got %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
