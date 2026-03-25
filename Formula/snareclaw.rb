# Homebrew formula for SnareClaw
# Install: brew install 0xDefence/tap/snareclaw
# Or:      brew tap 0xDefence/tap && brew install snareclaw

class Snareclaw < Formula
  include Language::Python::Virtualenv

  desc "Ambient supply chain security monitor for Python environments"
  homepage "https://github.com/0xDefence/snareclaw-py"
  url "https://github.com/0xDefence/snareclaw-py/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "UPDATE_WITH_ACTUAL_SHA256"
  license "MIT"

  depends_on "python@3.12"

  resource "click" do
    url "https://files.pythonhosted.org/packages/96/d3/f04c7bfcf5c1862a2a5b845c6b2b360488cf47af55dfa79c98f6a6bf98b5/click-8.1.7.tar.gz"
    sha256 "ca9853ad459e787e2192211578cc907e7594e294c7ccc834310722b41b9ca6de"
  end

  resource "httpx" do
    url "https://files.pythonhosted.org/packages/06/94/82699a10bca87a5556c9c59b5963/httpx-0.28.1.tar.gz"
    sha256 "UPDATE_WITH_ACTUAL_SHA256"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/a1/53/830aa4c3066a8ab0ae9a9955976fb770f29f0c91e68990104063e4afb5b3/rich-14.0.0.tar.gz"
    sha256 "UPDATE_WITH_ACTUAL_SHA256"
  end

  resource "watchdog" do
    url "https://files.pythonhosted.org/packages/watchdog-6.0.0.tar.gz"
    sha256 "UPDATE_WITH_ACTUAL_SHA256"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "snareclaw", shell_output("#{bin}/snare --version")
  end
end
