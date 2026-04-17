class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.14.0"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.0/nowifi-darwin-arm64.tar.gz"
      sha256 "1ff1f47e530d3bb54a8b67e8629e4eb8b93a1983e9cd508f9a4b7a826a2a2a15"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.0/nowifi-darwin-amd64.tar.gz"
      sha256 "e5f8aeb40643305ac1e4de1cce5cd1b50dfe64955e5496f9efb084dc460b7139"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.0/nowifi-linux-arm64.tar.gz"
      sha256 "ba753b4c9dd3a8ac30038a123865bcfcd192558eddc67f0306833c030bf6ee42"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.0/nowifi-linux-amd64.tar.gz"
      sha256 "609fa37d841be445aea1888211897ba8b4e4ff84793f1fe0e9f006a1100c35fb"
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
