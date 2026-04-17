class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.11.1"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.11.1/nowifi-darwin-arm64.tar.gz"
      sha256 "7f2d215b886af1b3a5d26d557fb73c427885fdb8c212036c48a00e5d944ed82c"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.11.1/nowifi-darwin-amd64.tar.gz"
      sha256 "6d8fd615552366e1ae1fa1c52b87ecec38663684850c1def4be703c2f18d195d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.11.1/nowifi-linux-arm64.tar.gz"
      sha256 "3f97b6d63ab93b59eabbe16e1cfa98a9e60c5649d5c7ebacdd07e421678fe3bd"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.11.1/nowifi-linux-amd64.tar.gz"
      sha256 "20eb74b0cff684ecc68ee8f0ca275357c4f804d44630de6d366d6912b398f411"
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
