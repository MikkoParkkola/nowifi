class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.13.0"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.13.0/nowifi-darwin-arm64.tar.gz"
      sha256 "02bf5e6d9bf8a1f6b5cc657ba0e3dd9e89291b950f1c9f550c37408c840e1a5c"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.13.0/nowifi-darwin-amd64.tar.gz"
      sha256 "2759db87ea640ed5016ffa0e83ec153932561c81888e5f636e0d00957bf07672"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.13.0/nowifi-linux-arm64.tar.gz"
      sha256 "69d2da595da15e9c960f0309f3e1cf6e9c839ee609d44d5615928747e5f53afa"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.13.0/nowifi-linux-amd64.tar.gz"
      sha256 "c8b552b2aff6371bae99a6da0d37b9e1cf2a3dbe80099c1694397ea9304fd30f"
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
