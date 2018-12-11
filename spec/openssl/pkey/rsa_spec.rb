require_relative "../../spec_helper"

require "openssl/x509/spki"
require "openssl/pkey/rsa"

describe OpenSSL::PKey::RSA do
  let(:pkey) { OpenSSL::PKey::RSA.new(2048) }

  describe "#to_spki" do
    it "returns an SPKI object" do
      expect(pkey.to_spki).to be_an(OpenSSL::X509::SPKI)
    end

    it "is the same SPKI structure as the original key" do
      expect(pkey.to_spki.spki_fingerprint.hexdigest).to eq(Digest::SHA256.hexdigest(pkey.public_key.to_der))
    end
  end
end
