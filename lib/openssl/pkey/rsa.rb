require "openssl/x509/spki"

module OpenSSL
  module PKey
    class RSA
      # Generate an OpenSSL::X509::SPKI structure for this public key
      def to_spki(_format = nil)
        OpenSSL::X509::SPKI.new(self.public_key.to_der)
      end
    end
  end
end
