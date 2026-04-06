class Nowifi < Formula
  desc "WiFi security assessment tool for captive portals and WPA audits"
  homepage "https://github.com/MikkoParkkola/nowifi"
  url "https://github.com/MikkoParkkola/nowifi/archive/refs/tags/v0.5.1.tar.gz"
  sha256 "a490a249cc5b08eca22ab8700992a2500e143e96227b9f26c75fa3d2e35ed546"
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
