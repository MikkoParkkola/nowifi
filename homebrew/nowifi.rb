# typed: strict
# frozen_string_literal: true

# Formula for the nowifi CLI binary releases.
class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  version "0.14.3"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.3/nowifi-darwin-arm64.tar.gz"
      sha256 "bbb34678f157a76b89d878d886c9845e3cc7d1cbfe88cb98902840a6643005f7"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.3/nowifi-darwin-amd64.tar.gz"
      sha256 "c351729597af59a59918ce2262855871ca5cf448a375185ab06bba1f1c6d8670"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.3/nowifi-linux-arm64.tar.gz"
      sha256 "73b17663b166de1a12ec9117a64a9f866f5b82c5a155155df266d29bd6a3af28"
    end
    on_intel do
      url "https://github.com/MikkoParkkola/nowifi/releases/download/v0.14.3/nowifi-linux-amd64.tar.gz"
      sha256 "ae4d18ded5cf42a26725e0ebf37a1266aa0429a1980f72647ab3687d962c0cb8"
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
