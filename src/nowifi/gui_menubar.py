"""macOS menubar app for nowifi. Shield icon, one-click audit."""

from __future__ import annotations

import subprocess
import threading

import rumps


class NoWiFiApp(rumps.App):
    """Menubar app that runs nowifi audit in the background."""

    def __init__(self):
        super().__init__(
            "NW",
            title="NW",
            quit_button=rumps.MenuItem("Quit", key="q"),
        )
        self._running = False
        self._process: subprocess.Popen | None = None
        self.menu = [
            rumps.MenuItem("Run Audit", callback=self._on_audit, key="r"),
            rumps.MenuItem("Probe Only", callback=self._on_probe),
            rumps.MenuItem("Open Dashboard", callback=self._on_dashboard),
            None,  # separator
            rumps.MenuItem("Reset Network", callback=self._on_reset),
            None,
        ]

    def _on_audit(self, sender):
        if self._running:
            rumps.notification("nowifi", "Already running", "An audit is in progress.")
            return
        self._running = True
        self.title = "NW*"
        threading.Thread(target=self._run_command, args=(["sudo", "nowifi", "--fast"],), daemon=True).start()

    def _on_probe(self, sender):
        if self._running:
            return
        self._running = True
        self.title = "NW*"
        threading.Thread(target=self._run_command, args=(["nowifi", "-p", "--fast"],), daemon=True).start()

    def _on_dashboard(self, sender):
        subprocess.Popen(["open", "http://127.0.0.1:8321"])

    def _on_reset(self, sender):
        if self._process and self._process.poll() is None:
            self._process.terminate()
        threading.Thread(target=self._run_command, args=(["sudo", "nowifi", "reset"],), daemon=True).start()

    def _run_command(self, cmd: list[str]):
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self._process.wait()
            exit_code = self._process.returncode

            if exit_code == 0:
                rumps.notification("nowifi", "Complete", "Audit finished successfully.")
            else:
                rumps.notification("nowifi", "Finished", f"Exit code: {exit_code}")
        except Exception as e:
            rumps.notification("nowifi", "Error", str(e)[:100])
        finally:
            self._running = False
            self.title = "NW"
            self._process = None


def run_menubar():
    """Launch the menubar app."""
    NoWiFiApp().run()


if __name__ == "__main__":
    run_menubar()
