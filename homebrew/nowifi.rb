class Nowifi < Formula
  include Language::Python::Virtualenv

  desc "WiFi security assessment tool - 23 bypass techniques"
  homepage "https://github.com/MikkoParkkola/nowifi"
  url "https://github.com/MikkoParkkola/nowifi/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "FILL_WHEN_TAG_CREATED"
  license "AGPL-3.0-or-later"

  depends_on "python@3.12"

  resource "click" do
    url "https://files.pythonhosted.org/packages/96/d3/f04c7bfcf5c1862a2a5b845c6b2b360488cf47af55dfa79c98f6a6bf98b5/click-8.1.7.tar.gz"
    sha256 "ca9853ad459e787e2192211578cc907e7594e294c7ccc834310722b41b9ca6de"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/b3/73/01b4c12e91c17c7c92838e9a3f28abb3f9cb07cee0e2fa69c0f53a0b2a06/rich-13.9.4.tar.gz"
    sha256 "439594978a49a09530cff7ebc4b5c7103ef57c6370b65e5a1a0e54162c5d4920"
  end

  resource "requests" do
    url "https://files.pythonhosted.org/packages/63/70/2bf7780ad2d390a8d301ad0b550f1581eadbd9a20f896afe06353c2a2913/requests-2.32.3.tar.gz"
    sha256 "55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760"
  end

  resource "dnspython" do
    url "https://files.pythonhosted.org/packages/37/7d/c871f55054e403fdfd6b8f65fd6d1c4e147ed100d3e9f9ba1fe695403939/dnspython-2.7.0.tar.gz"
    sha256 "ce9c432eda0dc91cf618a5cedf1a4571c67b571f79f8c9f3b4c1e56a0e8ef3ec"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/nowifi --version")
  end
end
