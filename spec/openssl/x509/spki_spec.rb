require_relative "../../spec_helper"

require "openssl/x509/spki"
require "openssl"

describe OpenSSL::X509::SPKI do
  let(:algorithm) { OpenSSL::ASN1::ObjectId.new("rsaEncryption") }
  let(:parameters) { OpenSSL::ASN1::Null.new(nil) }
  let(:key_data) { OpenSSL::ASN1::BitString.new("thisisnotarealpublickey") }

  let(:algorithm_identifier) do
    OpenSSL::ASN1::Sequence.new([algorithm, parameters].compact)
  end

  let(:spki_asn1) do
    OpenSSL::ASN1::Sequence.new([algorithm_identifier, key_data].compact)
  end

  describe ".new" do
    shared_examples :constructor_validation do
      context "with all fields present and correct" do
        it "succeeds" do
          expect { spki }.to_not raise_error
        end
      end
      
      context "without parameters" do
        let(:parameters) { nil }

        it "succeeds" do
          expect { spki }.to_not raise_error
        end
      end

      context "without key info" do
        let(:key_data) { nil }

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end

      context "when the key info isn't a BitString" do
        let(:key_data) { OpenSSL::ASN1::Integer.new(42) }

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end

      context "when the algorithm is missing" do
        let(:algorithm) { nil }

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end

      context "when the algorithm isn't an Object ID" do
        let(:algorithm) { OpenSSL::ASN1::Integer.new(42) }

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end
    end

    shared_examples :validate_provided_asn1 do
      context "when the SPKI data isn't a sequence" do
        let(:spki_asn1) { OpenSSL::ASN1::Set.new([algorithm_identifier, key_data]) }

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end

      context "with an extra element in the SPKI sequence" do
        let(:spki_asn1) do
          OpenSSL::ASN1::Sequence.new([algorithm_identifier, key_data, OpenSSL::ASN1::Null.new(nil)])
        end

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end

      context "with an extra element in the algorithm sequence" do
        let(:algorithm_identifier) do
          OpenSSL::ASN1::Sequence.new([algorithm, parameters, OpenSSL::ASN1::Integer.new(42)])
        end

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end

      context "when the algorithm identifier isn't a sequence" do
        let(:algorithm_identifier) do
          OpenSSL::ASN1::Set.new([algorithm, parameters])
        end

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end
    end

    context "with a single argument" do
      let(:spki) { OpenSSL::X509::SPKI.new(arg) }

      context "when the argument isn't a string or ASN1 sequence" do
        let(:arg) { 42 }

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end

      context "when passing an ASN1 object" do
        let(:arg) { spki_asn1 }

        include_examples :constructor_validation
        include_examples :validate_provided_asn1
      end

      context "when passing a string" do
        let(:arg) { spki_asn1.to_der }

        include_examples :constructor_validation
        include_examples :validate_provided_asn1
      end

      context "when passing some other type" do
        let(:arg) { 42 }

        it "explodes" do
          expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
        end
      end
    end

    context "with three arguments" do
      context "when passing ASN.1 objects" do
        let(:spki) { OpenSSL::X509::SPKI.new(algorithm, parameters, key_data) }

        include_examples :constructor_validation
      end

      context "when passing strings" do
        let(:spki) do
          OpenSSL::X509::SPKI.new(algorithm&.value, parameters&.value, key_data&.value)
        end

        include_examples :constructor_validation
      end
    end

    context "with two arguments" do
      let(:spki) { OpenSSL::X509::SPKI.new(algorithm, key_data) }

      it "explodes" do
        expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
      end
    end

    context "with many arguments" do
      let(:spki) { OpenSSL::X509::SPKI.new(algorithm, parameters, key_data, "ohai", "there", 42) }

      it "explodes" do
        expect { spki }.to raise_error(OpenSSL::X509::SPKIError)
      end
    end
  end

  describe "#to_der" do
    let(:spki) { OpenSSL::X509::SPKI.new(spki_asn1) }

    it "returns the DER encoded SPKI structure" do
      expect(spki.to_der).to eq(spki_asn1.to_der)
    end
  end

  describe "#to_key" do
    let(:spki) { OpenSSL::X509::SPKI.new(OpenSSL::PKey::RSA.new(2048).public_key.to_der) }

    it "returns a key" do
      expect(spki.to_key).to be_a(OpenSSL::PKey::RSA)
    end
  end

  describe "#key_fingerprint" do
    let(:spki) { OpenSSL::X509::SPKI.new(spki_asn1) }

    it "returns a SHA1 digest by default" do
      expect(spki.key_fingerprint).to be_an(OpenSSL::Digest::SHA1)
    end

    it "returns a SHA256 digest if you ask for one" do
      expect(spki.key_fingerprint(OpenSSL::Digest::SHA256)).to be_an(OpenSSL::Digest::SHA256)
    end

    it "returns a digest of *just* the key material" do
      expect(spki.key_fingerprint.hexdigest).to eq(Digest::SHA1.hexdigest(key_data.value))
    end
  end

  describe "#spki_fingerprint" do
    let(:spki) { OpenSSL::X509::SPKI.new(spki_asn1) }

    it "returns a SHA256 digest by default" do
      expect(spki.spki_fingerprint).to be_an(OpenSSL::Digest::SHA256)
    end

    it "returns a SHA1 digest if you ask for one" do
      expect(spki.spki_fingerprint(OpenSSL::Digest::SHA1)).to be_an(OpenSSL::Digest::SHA1)
    end

    it "returns a digest of the whole structure" do
      expect(spki.spki_fingerprint.hexdigest).to eq(Digest::SHA256.hexdigest(spki_asn1.to_der))
    end
  end
end
