// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"context"
)

func init() { Register(&digitalOceanProvider{}) }

type digitalOceanProvider struct{}

func (digitalOceanProvider) Name() string { return "digitalocean" }

func (digitalOceanProvider) Create(_ context.Context, opts CreateOpts) (*Info, error) {
	token, err := getToken("digitalocean", opts.APIToken)
	if err != nil {
		return nil, err
	}
	return createDigitalOcean(token, opts.TTLHours)
}

func (digitalOceanProvider) Destroy(_ context.Context, info *Info, apiToken string) error {
	token, err := getToken("digitalocean", apiToken)
	if err != nil {
		return err
	}
	return destroyDigitalOcean(token, info.ServerID)
}
