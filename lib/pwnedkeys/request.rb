require "base64"
require "json"
require "net/http"
require "openssl"

require "openssl/pkey/rsa"
require "openssl/pkey/ec"

module Pwnedkeys
  class Request
    class Error < StandardError; end
    class VerificationError < Error; end

    def initialize(spki)
      @spki = if spki.is_a?(OpenSSL::X509::SPKI)
        spki
      elsif spki.is_a?(String)
        begin
          OpenSSL::X509::SPKI.new(spki)
        rescue OpenSSL::ASN1::ASN1Error, OpenSSL::X509::SPKIError
          raise Error,
                "Invalid SPKI ASN.1 string"
        end
      else
        raise Error,
              "Invalid argument type passed to Pwnedkeys::Request.new (need OpenSSL::X509::SPKI or string, got #{spki.class})"
      end

      # Verify key type is OK
      key_params
    end

    def pwned?
      retry_count = 10

      loop do
        uri = URI(ENV["PWNEDKEYS_API_URL"] || "https://v1.pwnedkeys.com")
        uri.path += "/#{@spki.spki_fingerprint.hexdigest}"

        res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
          req = Net::HTTP::Get.new(uri.path)
          req["User-Agent"] = "pwnedkeys-tools/0.0.0"
          http.request(req)
        end

        if res.code == "200"
          verify!(res.body)
          return true
        elsif res.code == "404"
          return false
        elsif (500..599) === res.code.to_i && retry_count > 0
          # Server-side error, let's try a few more times
          sleep 1
          retry_count -= 1
        else
          raise Error,
                "Unable to determine pwnage, error status code returned from #{uri}: #{res.code}"
        end
      end
    end

    private

    def verify!(res)
      json = JSON.parse(res)
      header = JSON.parse(unb64(json["protected"]))

      key = @spki.to_key

      verify_data = "#{json["protected"]}.#{json["payload"]}"

      unless key.verify(hash_func.new, format_sig(unb64(json["signature"])), verify_data)
        raise VerificationError,
              "Response signature cannot be validated by provided key"
      end

      unless header["alg"] == key_alg
        raise VerificationError,
              "Incorrect alg parameter.  Got #{header["alg"]}, expected #{key_alg} for #{key.class} key"
      end

      unless header["kid"] == @spki.spki_fingerprint.hexdigest
        raise VerificationError,
              "Key ID in response doesn't match.  Got #{header["kid"]}, expected #{@spki.spki_fingerprint.hexdigest}"
      end

      unless unb64(json["payload"]) =~ /key is pwned/
        raise VerificationError,
              "Response payload does not include magic string 'key is pwned', got #{unb64(json["payload"])}"
      end

      # The gauntlet has been run and you have been found... worthy
    end

    def unb64(s)
      Base64.urlsafe_decode64(s)
    end

    def key_alg
      key_params[:key_alg]
    end

    def hash_func
      key_params[:hash_func]
    end

    def format_sig(sig)
      key_params[:format_sig].call(sig)
    end

    def ec_sig(jose_sig)
      # *Real* EC signatures are a two-element ASN.1 sequence containing
      # the R and S values.  RFC7518, in its infinite wisdom, has decided that
      # that is not good enough, and instead it wants the signatures in raw
      # concatenated R/S as octet strings.  Because of *course* it does.
      OpenSSL::ASN1::Sequence.new(split_in_two_equal_halves(jose_sig).map do |i|
        OpenSSL::ASN1::Integer.new(i.unpack("C*").inject(0) { |v, i| v * 256 + i })
      end).to_der
    end

    def split_in_two_equal_halves(s)
      [s[0..(s.length / 2 - 1)], s[(s.length / 2)..(s.length - 1)]]
    end

    def key_params
      case @spki.to_key
      when OpenSSL::PKey::RSA then {
        key_alg: "RS256",
        hash_func: OpenSSL::Digest::SHA256,
        format_sig: ->(sig) { sig },
      }
      when OpenSSL::PKey::EC
        case @spki.to_key.public_key.group.curve_name
        when "prime256v1" then {
          key_alg: "ES256",
          hash_func: OpenSSL::Digest::SHA256,
          format_sig: ->(sig) { ec_sig(sig) },
        }
        when "secp384r1"  then {
          key_alg: "ES384",
          hash_func: OpenSSL::Digest::SHA384,
          format_sig: ->(sig) { ec_sig(sig) },
        }
        when "secp521r1"  then {
          key_alg: "ES512",
          hash_func: OpenSSL::Digest::SHA512,
          # The components of P-521 keys are 521 bits each, which is padded
          # out to be 528 bits -- 66 octets.
          format_sig: ->(sig) { ec_sig(sig) },
        }
        else
          raise Error, "EC key containing unsupported curve #{@spki.to_key.group.curve_name}"
        end
      else
        raise Error, "Unsupported key type #{@key.class}"
      end
    end
  end
end
