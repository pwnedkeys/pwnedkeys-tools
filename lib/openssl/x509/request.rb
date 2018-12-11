require "openssl/x509/spki"

module OpenSSL
  module X509
    class Request
      # Generate an OpenSSL::X509::SPKI structure for the public key in the CSR
      def to_spki(_format = nil)
        OpenSSL::X509::SPKI.new(self.public_key.to_der)
      end
    end
  end
end
