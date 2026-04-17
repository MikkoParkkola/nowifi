// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"context"
)

func init() { Register(&hetznerProvider{}) }

type hetznerProvider struct{}

func (hetznerProvider) Name() string { return "hetzner" }

func (hetznerProvider) Create(_ context.Context, opts CreateOpts) (*Info, error) {
	token, err := getToken("hetzner", opts.APIToken)
	if err != nil {
		return nil, err
	}
	return createHetzner(token, opts.TTLHours)
}

func (hetznerProvider) Destroy(_ context.Context, info *Info, apiToken string) error {
	token, err := getToken("hetzner", apiToken)
	if err != nil {
		return err
	}
	return destroyHetzner(token, info.ServerID)
}
