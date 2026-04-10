class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.5.2"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.5.2/nowifi-darwin-arm64.tar.gz"
      sha256 "4fa017e2975713079494d99c446f06d8a66c9b2f7a27a68a0577e52dd205aae3"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.5.2/nowifi-darwin-amd64.tar.gz"
      sha256 "6b4dd4b2a2da8bf4bcd154d1f3c06164b3a337285a552d3e67df0a3c4b324a63"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.5.2/nowifi-linux-arm64.tar.gz"
      sha256 "f03757c36da6184bd27a165174e0dd0ac403c8c7351d40d8b7a41dcccc2ed973"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.5.2/nowifi-linux-amd64.tar.gz"
      sha256 "b2722467e54ed3042503652256e2b97d6b1ad71ce1f617068a0715b1770b7a0f"
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
