require "openssl/x509/spki"

module OpenSSL
  module X509
    class Certificate
      # Generate an OpenSSL::X509::SPKI structure for the public key in the cert
      def to_spki(_format = nil)
        OpenSSL::X509::SPKI.new(self.public_key.to_der)
      end
    end
  end
end
