require_relative "../../spec_helper"

require "openssl/x509/certificate"

describe OpenSSL::X509::Certificate do
  let(:key) { OpenSSL::PKey::RSA.new(2048) }
  let(:crt) do
    OpenSSL::X509::Certificate.new.tap do |crt|
      crt.version    = 2
      crt.serial     = 1
      crt.subject    = OpenSSL::X509::Name.new([["CN", "lolrus"]])
      crt.issuer     = crt.subject
      crt.public_key = key.public_key

      crt.sign(key, OpenSSL::Digest::SHA256.new)
    end
  end

  describe "#to_spki" do
    it "returns an SPKI object" do
      expect(crt.to_spki).to be_an(OpenSSL::X509::SPKI)
    end

    it "is the same SPKI structure as the original key" do
      expect(crt.to_spki.spki_fingerprint.hexdigest).to eq(Digest::SHA256.hexdigest(key.public_key.to_der))
    end
  end
end
