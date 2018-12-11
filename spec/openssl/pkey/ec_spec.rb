require_relative "../../spec_helper"

require "openssl/x509/spki"
require "openssl/pkey/ec"

describe OpenSSL::PKey::EC do
  let(:pkey) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

  describe "#to_spki" do
    it "returns an SPKI object" do
      expect(pkey.to_spki).to be_an(OpenSSL::X509::SPKI)
    end

    it "is the same SPKI structure as the original uncompressed key" do
      spki = OpenSSL::ASN1::Sequence.new(
        [
          OpenSSL::ASN1::Sequence.new(
            [
              OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
              OpenSSL::ASN1::ObjectId.new("prime256v1"),
            ]
          ),
          OpenSSL::ASN1::BitString.new(pkey.public_key.to_octet_string(:uncompressed))
        ]
      )

      expect(pkey.to_spki.spki_fingerprint.hexdigest).to eq(Digest::SHA256.hexdigest(spki.to_der))
    end

    it "is the same SPKI structure as the original compressed key" do
      spki = OpenSSL::ASN1::Sequence.new(
        [
          OpenSSL::ASN1::Sequence.new(
            [
              OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
              OpenSSL::ASN1::ObjectId.new("prime256v1"),
            ]
          ),
          OpenSSL::ASN1::BitString.new(pkey.public_key.to_octet_string(:compressed))
        ]
      )

      expect(pkey.to_spki(:compressed).spki_fingerprint.hexdigest).to eq(Digest::SHA256.hexdigest(spki.to_der))
    end

    it "explodes if you don't generate the key first" do
      expect { OpenSSL::PKey::EC.new("prime256v1").to_spki }.to raise_error(OpenSSL::PKey::ECError)
    end
  end
end
