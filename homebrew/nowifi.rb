class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.14.0"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.0/nowifi-darwin-arm64.tar.gz"
      sha256 "17480e88a4a9de9c82455835f3d2669453bad67e3a60705bd7e8e45aeffb066f"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.0/nowifi-darwin-amd64.tar.gz"
      sha256 "c434e626e3c1fad2c76ab38f43f65fc7bd42d32b945601da4471510af25a35a3"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.0/nowifi-linux-arm64.tar.gz"
      sha256 "405c23cb29abc899be838a6aba82f87ef33c39270e9b515d0e4ef6b77141e9d9"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.0/nowifi-linux-amd64.tar.gz"
      sha256 "6376692d29c419f9896a8473a678eb6220606beb5cd61836bc936474d2ba2b5b"
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
