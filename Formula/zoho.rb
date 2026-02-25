class Zoho < Formula
  include Language::Python::Virtualenv

  desc "Manage Zoho Mail email aliases from the command line"
  homepage "https://github.com/costajor/zoho-mail"
  url "https://github.com/costajor/zoho-mail/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "FILL_IN_AFTER_TAGGING" # run: shasum -a 256 <downloaded tarball>
  license "MIT"
  head "https://github.com/costajor/zoho-mail.git", branch: "main"

  depends_on "python@3.13"

  # To regenerate resource hashes after updating dependencies, run:
  #   brew update-python-resources Formula/zoho.rb
  resource "requests" do
    url "https://files.pythonhosted.org/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/requests-2.32.3.tar.gz"
    sha256 "55365417734eb18255590a9f9f43c7c8da952fba57daa08a564c2028d9c2cf32"
  end

  resource "certifi" do
    url "https://files.pythonhosted.org/packages/b0/ee/9b19140fe824b367c04c5e1b369942dd754c4c5462d5674002f75c4dedc1/certifi-2024.12.14.tar.gz"
    sha256 "b650d30f370c2b724812bee08008be0c4163b163ddaec3f2546c1caf65f191db"
  end

  resource "charset-normalizer" do
    url "https://files.pythonhosted.org/packages/16/b0/572805e227f01586461c80e0fd25d65a2115599cc9dad8d5de4c5ef2879b/charset_normalizer-3.4.1.tar.gz"
    sha256 "44251f18cd68a75b56585dd00dae26183e102cd5e0f9f1466e6df5da2ed64ea3"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/f1/70/7703c29685631f5a7d1d69d6f8b887b485163e4a0e74e8c5a49d4e7b8e4d/idna-3.10.tar.gz"
    sha256 "12f65c9b470abda6dc35cf9407f7fbed40ea8a3a93ddf39823fd2d44e5f6e12c"
  end

  resource "urllib3" do
    url "https://files.pythonhosted.org/packages/ed/63/22ba4ebfe7430b76388e7cd448d5478814d3032121827c12a2cc287e2260/urllib3-2.3.0.tar.gz"
    sha256 "e46cc83e70dbf3e3fea3ab7e2761f2ad401e1b9f586dd41722c5c8b78b79f87f"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "usage:", shell_output("#{bin}/zoho --help 2>&1")
  end
end
