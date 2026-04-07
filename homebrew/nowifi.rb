class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  url "https://github.com/MikkoParkkola/nowifi/archive/refs/tags/v0.5.2.tar.gz"
  sha256 "b338350fa4e3512f3115c62da66473308e78c194e5af0598839b5914467904d9"
  license "AGPL-3.0-or-later"

  depends_on "go" => :build

  def install
    cd "go" do
      ldflags = "-s -w -X main.version=#{version}"
      system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/nowifi"
    end
  end

  test do
    assert_match "nowifi v#{version}", shell_output("#{bin}/nowifi --version")
  end
end
