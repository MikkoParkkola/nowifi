// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"context"
)

func init() { Register(&cfQuickProvider{}) }

type cfQuickProvider struct{}

func (cfQuickProvider) Name() string { return "cloudflare_quick" }

func (cfQuickProvider) Create(ctx context.Context, opts CreateOpts) (*Info, error) {
	// The provider interface does not foreground the tunnel.  The stop func is
	// discarded here; callers using the registry path (e.g. setup cascade) are
	// expected to use DestroyServer / SIGKILL on the PID when done.
	info, _, err := SetupCloudflareQuickTunnelWithOpts(ctx, opts)
	return info, err
}

func (cfQuickProvider) Destroy(ctx context.Context, info *Info, _ string) error {
	return destroyCloudflareQuick(info)
}
