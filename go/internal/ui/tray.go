//go:build darwin && cgo

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package ui

import (
	"fmt"
	"os/exec"

	"github.com/getlantern/systray"
)

// RunTray starts the macOS system tray / menubar application.
// It blocks until the user quits.
func RunTray(dashboardPort int) {
	onReady := func() {
		systray.SetTitle("NW")
		systray.SetTooltip("nowifi -- No WiFi? Now WiFi.")

		mAudit := systray.AddMenuItem("Run Audit", "Run full audit pipeline (sudo)")
		mDiagnose := systray.AddMenuItem("Diagnose", "Read-only network assessment")
		mProbe := systray.AddMenuItem("Probe Only", "Probe protocols only")
		systray.AddSeparator()
		mDashboard := systray.AddMenuItem("Open Dashboard", fmt.Sprintf("http://127.0.0.1:%d", dashboardPort))
		systray.AddSeparator()
		mReset := systray.AddMenuItem("Reset Network", "Emergency network cleanup")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit", "Exit nowifi menubar")

		go func() {
			for {
				select {
				case <-mAudit.ClickedCh:
					go func() {
						AppendLog("Menubar: Run Audit triggered")
						state.mu.Lock()
						if state.Status == "idle" || state.Status == "error" {
							state.Status = "probing"
							state.mu.Unlock()
							runAuditBackground()
						} else {
							state.mu.Unlock()
							AppendLog("Menubar: busy, ignoring audit request")
						}
					}()

				case <-mDiagnose.ClickedCh:
					go func() {
						AppendLog("Menubar: Diagnose triggered")
						state.mu.Lock()
						if state.Status == "idle" || state.Status == "error" {
							state.Status = "diagnosing"
							state.mu.Unlock()
							runDiagnoseBackground()
						} else {
							state.mu.Unlock()
							AppendLog("Menubar: busy, ignoring diagnose request")
						}
					}()

				case <-mProbe.ClickedCh:
					go func() {
						AppendLog("Menubar: Probe triggered")
						state.mu.Lock()
						if state.Status == "idle" || state.Status == "error" {
							state.Status = "probing"
							state.mu.Unlock()
							runProbeBackground()
						} else {
							state.mu.Unlock()
							AppendLog("Menubar: busy, ignoring probe request")
						}
					}()

				case <-mDashboard.ClickedCh:
					url := fmt.Sprintf("http://127.0.0.1:%d", dashboardPort)
					AppendLog(fmt.Sprintf("Menubar: Opening %s", url))
					_ = exec.Command("open", url).Start()

				case <-mReset.ClickedCh:
					go func() {
						AppendLog("Menubar: Reset triggered")
						runResetBackground()
					}()

				case <-mQuit.ClickedCh:
					systray.Quit()
					return
				}
			}
		}()
	}

	onExit := func() {
		AppendLog("Menubar: exiting")
	}

	systray.Run(onReady, onExit)
}
