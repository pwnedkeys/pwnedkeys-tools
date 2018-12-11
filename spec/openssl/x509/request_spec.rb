require_relative "../../spec_helper"

require "openssl/x509/request"

describe OpenSSL::X509::Request do
  let(:key) { OpenSSL::PKey::RSA.new(2048) }
  let(:req) do
    OpenSSL::X509::Request.new.tap do |csr|
      csr.version    = 0
      csr.subject    = OpenSSL::X509::Name.new([["CN", "lolrus"]])
      csr.public_key = key.public_key
      csr.sign(key, OpenSSL::Digest::SHA256.new)
    end
  end

  describe "#to_spki" do
    it "returns an SPKI object" do
      expect(req.to_spki).to be_an(OpenSSL::X509::SPKI)
    end

    it "is the same SPKI structure as the original key" do
      expect(req.to_spki.spki_fingerprint.hexdigest).to eq(Digest::SHA256.hexdigest(key.public_key.to_der))
    end
  end
end
