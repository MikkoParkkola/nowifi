// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"context"
)

func init() { Register(&cfWorkerProvider{}) }

type cfWorkerProvider struct{}

func (cfWorkerProvider) Name() string { return "cloudflare_worker" }

func (cfWorkerProvider) Create(_ context.Context, _ CreateOpts) (*Info, error) {
	return SetupCloudflareWorker()
}

func (cfWorkerProvider) Destroy(_ context.Context, info *Info, _ string) error {
	return destroyCloudflareWorker(info.ServerID)
}
