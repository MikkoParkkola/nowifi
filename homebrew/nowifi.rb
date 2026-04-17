class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.12.0"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.12.0/nowifi-darwin-arm64.tar.gz"
      sha256 "32d4aa255f83a58885057f8ca7e65986fc61d81da05d9fee48b14a8fc1f0edf3"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.12.0/nowifi-darwin-amd64.tar.gz"
      sha256 "b86869f442ad8d0d209a25de56dc8779a711155bb5798b7ceebe73af56976900"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.12.0/nowifi-linux-arm64.tar.gz"
      sha256 "ad0c0a725b276ce90d794c49268faed2bb94d714d60b0f71a343530bf161669f"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.12.0/nowifi-linux-amd64.tar.gz"
      sha256 "e33e205452c22fe7068e506f39400b4fe7b9011b5caea22d4141aa3ab51084bd"
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
