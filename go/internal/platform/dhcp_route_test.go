// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

//go:build darwin || linux

package platform

import "testing"

func TestDHCPRoute_IsDefault(t *testing.T) {
	tests := []struct {
		in   DHCPRoute
		want bool
	}{
		{DHCPRoute{CIDR: "0.0.0.0/0"}, true},
		{DHCPRoute{CIDR: "::/0"}, true},
		{DHCPRoute{CIDR: "10.0.0.0/8"}, false},
		{DHCPRoute{CIDR: ""}, false},
	}
	for _, tc := range tests {
		if got := tc.in.IsDefault(); got != tc.want {
			t.Errorf("IsDefault(%q) = %v, want %v", tc.in.CIDR, got, tc.want)
		}
	}
}
