# typed: strict
# frozen_string_literal: true

# Formula for the nowifi CLI binary releases.
class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.16.0"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.16.0/nowifi-darwin-arm64.tar.gz"
      sha256 "3ce4ae213f7adc1bef3b5fa2d212975d3ffb93d0b68bfd8237ed207b01be9049"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.16.0/nowifi-darwin-amd64.tar.gz"
      sha256 "1edf6cc755258d1dcb826778a010564918070c65e1687b24287c4820b9d0cb23"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.16.0/nowifi-linux-arm64.tar.gz"
      sha256 "54bf8f956286eaa4c5f08978baa324e41ac67c048e3f83a43e67543c62137b1a"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.16.0/nowifi-linux-amd64.tar.gz"
      sha256 "4bb4d517444385d0d34276ed10cb42ddb4983051459f7d020b5804e912319fa3"
    end
  end

  def install
    # Each tarball contains a single bare binary named nowifi-<os>-<arch>.
    # Pick whatever is in the staging dir and install it as bin/nowifi.
    binary = Dir["nowifi-*"].first
    odie "no nowifi binary in tarball" unless binary
    bin.install binary => "nowifi"
  end

  test do
    assert_match "nowifi", shell_output("#{bin}/nowifi --version")
  end
end
