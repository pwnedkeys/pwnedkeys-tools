require "openssl/x509/spki"

module OpenSSL
  module PKey
    class EC
      # Generate an OpenSSL::X509::SPKI structure for this public key
      def to_spki(format = :uncompressed)
        unless self.public_key?
          raise ECError,
                "Cannot convert non-public-key to SPKI"
        end
        OpenSSL::X509::SPKI.new("id-ecPublicKey", OpenSSL::ASN1::ObjectId.new(self.public_key.group.curve_name), self.public_key.to_octet_string(format))
      end
    end
  end
end
