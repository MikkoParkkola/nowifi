class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.11.0"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.11.0/nowifi-darwin-arm64.tar.gz"
      sha256 "ee3ff3f24fb42c1a4a39634a8d1d4beafe088b7786ad20493f8246ff934c0f70"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.11.0/nowifi-darwin-amd64.tar.gz"
      sha256 "85cfc79250c42b18917242b64d38c16905faf4d8fc81510034d75c789979db92"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.11.0/nowifi-linux-arm64.tar.gz"
      sha256 "1923d9c95c61876543a92dc9ead549be929c51bfc13111174885980e48dc2e88"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.11.0/nowifi-linux-amd64.tar.gz"
      sha256 "c6362d49c313e5e2d71b9220a4b4b876ec64a00b22e90a58a62c5820a440587e"
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
