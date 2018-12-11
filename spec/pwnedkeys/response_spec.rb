require_relative "../spec_helper"

require "pwnedkeys/response"

describe Pwnedkeys::Response do
  describe ".new" do
    it "accepts a key object" do
      expect { described_class.new(OpenSSL::PKey::RSA.new(2048)) }.to_not raise_error
    end

    it "accepts a PEM string" do
      expect { described_class.new(OpenSSL::PKey::RSA.new(2048).to_pem) }.to_not raise_error
    end

    it "accepts a DER string" do
      expect { described_class.new(OpenSSL::PKey::RSA.new(2048).to_der) }.to_not raise_error
    end

    it "does not accept an unrecognised string" do
      expect { described_class.new("ohaithere") }.to raise_error(Pwnedkeys::Response::Error)
    end

    it "does not accept other types of argument" do
      expect { described_class.new(nil) }.to raise_error(Pwnedkeys::Response::Error)
      expect { described_class.new(42) }.to raise_error(Pwnedkeys::Response::Error)
      expect { described_class.new(:fortytwo) }.to raise_error(Pwnedkeys::Response::Error)
    end
  end

  describe "#to_json" do
    let(:res) { Pwnedkeys::Response.new(key) }
    let(:jws) { JSON.parse(res.to_json) }

    shared_examples :valid_response do
      it "returns a string" do
        expect(res.to_json).to be_a(String)
      end

      it "returns a valid JSON string" do
        expect { JSON.parse(res.to_json) }.to_not raise_error
      end

      context "the JSON response" do
        it "has a 'protected' key" do
          expect(jws).to have_key("protected")
        end

        it "has a 'payload' key" do
          expect(jws).to have_key("payload")
        end

        it "has a 'signature' key" do
          expect(jws).to have_key("signature")
        end

        context "the payload" do
          let(:payload) { jws["payload"] }

          it "is URL-compatible base64-encoded" do
            expect(payload).to match(/\A[a-zA-Z0-9_-]+\z/)
          end

          it "decodes to a string which includes 'key is pwned'" do
            expect(Base64.urlsafe_decode64(payload)).to match(/key is pwned/)
          end
        end

        context "the protected header" do
          let(:header) { jws["protected"] }

          it "is URL-compatible base64-encoded" do
            expect(header).to match(/\A[a-zA-Z0-9_-]+\z/)
          end

          it "decodes to valid JSON" do
            expect { JSON.parse(Base64.urlsafe_decode64(header)) }.to_not raise_error
          end
        end

        context "the signature" do
          let(:sig) { jws["signature"] }

          it "is URL-compatible base64-encoded" do
            expect(sig).to match(/\A[a-zA-Z0-9_-]+\z/)
          end
        end
      end
    end

    context "for an RSA key" do
      let(:key) { OpenSSL::PKey::RSA.new(2048) }

      include_examples :valid_response

      context "the protected header" do
        let(:header) { JSON.parse(Base64.urlsafe_decode64(jws["protected"])) }

        it "specifies the right alg" do
          expect(header["alg"]).to eq("RS256")
        end

        it "has the right key ID" do
          expect(header["kid"]).to eq(key.to_spki.spki_fingerprint.hexdigest)
        end
      end
      
      context "the signature" do
        let(:sig) { Base64.urlsafe_decode64(JSON.parse(res.to_json)["signature"]) }
        it "validates" do
          expect(key.verify(OpenSSL::Digest::SHA256.new, sig, "#{jws["protected"]}.#{jws["payload"]}")).to be(true)
        end
      end
    end

    def ec_sig(str)
      unless str.length % 2 == 0
        raise "Invalid signature string"
      end

      OpenSSL::ASN1::Sequence.new([str[0..(str.length / 2 - 1)], str[(str.length / 2)..(str.length - 1)]].map do |i|
        OpenSSL::ASN1::Integer.new(i.unpack("C*").inject(0) { |v, i| v * 256 + i })
      end).to_der
    end

    context "for a P-256 key" do
      let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

      include_examples :valid_response

      context "the protected header" do
        let(:header) { JSON.parse(Base64.urlsafe_decode64(jws["protected"])) }

        it "specifies the right alg" do
          expect(header["alg"]).to eq("ES256")
        end

        it "has the right key ID" do
          expect(header["kid"]).to eq(key.to_spki.spki_fingerprint.hexdigest)
        end
      end
      
      context "the signature" do
        let(:sig) { ec_sig(Base64.urlsafe_decode64(JSON.parse(res.to_json)["signature"])) }

        it "validates" do
          expect(key.verify(OpenSSL::Digest::SHA256.new, sig, "#{jws["protected"]}.#{jws["payload"]}")).to be(true)
        end
      end
    end

    context "for a P-384 key" do
      let(:key) { OpenSSL::PKey::EC.new("secp384r1").generate_key }

      include_examples :valid_response

      context "the protected header" do
        let(:header) { JSON.parse(Base64.urlsafe_decode64(jws["protected"])) }

        it "specifies the right alg" do
          expect(header["alg"]).to eq("ES384")
        end

        it "has the right key ID" do
          expect(header["kid"]).to eq(key.to_spki.spki_fingerprint.hexdigest)
        end
      end
      
      context "the signature" do
        let(:sig) { ec_sig(Base64.urlsafe_decode64(JSON.parse(res.to_json)["signature"])) }

        it "validates" do
          expect(key.verify(OpenSSL::Digest::SHA384.new, sig, "#{jws["protected"]}.#{jws["payload"]}")).to be(true)
        end
      end
    end

    context "for a P-521 key" do
      let(:key) { OpenSSL::PKey::EC.new("secp521r1").generate_key }

      include_examples :valid_response

      context "the protected header" do
        let(:header) { JSON.parse(Base64.urlsafe_decode64(jws["protected"])) }

        it "specifies the right alg" do
          expect(header["alg"]).to eq("ES512")
        end

        it "has the right key ID" do
          expect(header["kid"]).to eq(key.to_spki.spki_fingerprint.hexdigest)
        end
      end
      
      context "the signature" do
        let(:sig) { ec_sig(Base64.urlsafe_decode64(JSON.parse(res.to_json)["signature"])) }

        it "validates" do
          expect(key.verify(OpenSSL::Digest::SHA512.new, sig, "#{jws["protected"]}.#{jws["payload"]}")).to be(true)
        end
      end
    end

    context "for a Koblitz curve key" do
      let(:key) { OpenSSL::PKey::EC.new("secp256k1").generate_key }

      it "raises an error" do
        expect { res.to_json }.to raise_error(Pwnedkeys::Response::Error)
      end
    end

    context "for an unsupported key type" do
      let(:key) { OpenSSL::PKey::DSA.new(1024) }

      it "raises an error" do
        expect { res.to_json }.to raise_error(Pwnedkeys::Response::Error)
      end
    end
  end
end
