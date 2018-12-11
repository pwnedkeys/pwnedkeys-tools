require "base64"
require "json"
require "openssl"

require "openssl/pkey/rsa"
require "openssl/pkey/ec"

module Pwnedkeys
  class Response
    class Error < StandardError; end

    def initialize(key)
      @key = if key.kind_of?(OpenSSL::PKey::PKey)
        key
      elsif key.is_a?(String)
        begin
          OpenSSL::PKey.read(key)
        rescue OpenSSL::PKey::PKeyError
          raise Error,
                "Unable to parse provided key data"
        end
      else
        raise Error,
              "Invalid argument type passed to Pwnedkeys::Response.new (need OpenSSL::PKey::PKey or string, got #{key.class})"
      end
    end

    def to_json(*spki_format)
      header = {
        alg: key_alg,
        kid: @key.to_spki(*spki_format).spki_fingerprint.hexdigest,
      }

      obj = {
        payload:   b64("This key is pwned!  See https://pwnedkeys.com for more info."),
        protected: b64(header.to_json),
      }

      obj[:signature] = b64(sign(obj))
      obj.to_json
    end

    private

    def b64(s)
      Base64.urlsafe_encode64(s).sub(/=*\z/, '')
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

    def jose_sig(ec_sig, len)
      # EC signatures are a two-element ASN.1 sequence containing
      # the R and S values.  RFC7518, in its infinite wisdom, has decided that
      # that is not good enough, and instead it wants the signatures in raw
      # concatenated R/S as octet strings.  Because of *course* it does.
      OpenSSL::ASN1.decode(ec_sig).value.map { |n| [sprintf("%0#{len * 2}x", n.value)].pack("H*") }.join
    end

    def key_params
      case @key
      when OpenSSL::PKey::RSA then {
        key_alg: "RS256",
        hash_func: OpenSSL::Digest::SHA256,
        format_sig: ->(sig) { sig },
      }
      when OpenSSL::PKey::EC
        case @key.public_key.group.curve_name
        when "prime256v1" then {
          key_alg: "ES256",
          hash_func: OpenSSL::Digest::SHA256,
          format_sig: ->(sig) { jose_sig(sig, 32) },
        }
        when "secp384r1"  then {
          key_alg: "ES384",
          hash_func: OpenSSL::Digest::SHA384,
          format_sig: ->(sig) { jose_sig(sig, 48) },
        }
        when "secp521r1"  then {
          key_alg: "ES512",
          hash_func: OpenSSL::Digest::SHA512,
          # The components of P-521 keys are 521 bits each, which is padded
          # out to be 528 bits -- 66 octets.
          format_sig: ->(sig) { jose_sig(sig, 66) },
        }
        else
          raise Error, "EC key containing unsupported curve #{@key.public_key.group.curve_name}"
        end
      else
        raise Error, "Unsupported key type #{@key.class}"
      end
    end

    def sign(obj)
      format_sig(@key.sign(hash_func.new, obj[:protected] + "." + obj[:payload]))
    end
  end
end
