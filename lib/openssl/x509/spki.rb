require "openssl"

module OpenSSL
  module X509
    # Error raised when something goes awry in an SPKI object.
    #
    class SPKIError < OpenSSL::OpenSSLError; end

    # `subjectPublicKeyInfo` for everyone.
    #
    # A standardised representation of the `SubjectPublicKeyInfo` X.509
    # structure, along with helper methods to construct, deconstruct,
    # and derive useful results from such a structure.
    #
    class SPKI
      # Create a new SPKI object.
      #
      # This method can be called in one of a few different ways:
      # 
      # * `SPKI.new(String)` -- the provided string is interpreted as an ASN.1
      #   DER data stream representing a `SubjectPublicKeyInfo` structure.  If
      #
      #
      # * `SPKI.new(OpenSSL::ASN::Sequence) -- an already-decoded
      #   `SubjectPublicKeyInfo` structure, ready for inspection and manipulation.
      #
      # * `SPKI.new(String, Object, String) -- create a new SPKI from its
      #   component parts.  The first `String` is the OID of the
      #   `algorithm.algorithm` field, while the second string is the content of
      #   the `subjectPublicKey` field.  These will be converted into their ASN.1
      #   equivalents (ObjectID and BitString, respectively).  The second
      #   argument, the `Object`, is an arbitrary ASN.1 object representing
      #   whatever should go in the `algorithm.parameters` field.  If this
      #   field should be **absent**, this argument should be set to `nil`.
      #
      # * `SPKI.new(OpenSSL::ASN1::ObjectId, Object, OpenSSL::ASN1::BitString)` --
      #   this is equivalent to the above three-argument form, but the arguments
      #   are already in their ASN.1 object form, and won't be converted.  The
      #   `Object` argument has the same semantics as above.
      #
      # @raise [OpenSSL::X509::SPKIError] if the parameters passed don't meet
      #   validation requirements.  The exception message will provide more
      #   details as to what was unacceptable.
      #
      def initialize(*args)
        @spki = if args.length == 1
          if args.first.is_a?(String)
            OpenSSL::ASN1.decode(args.first)
          elsif args.first.is_a?(OpenSSL::ASN1::Sequence)
            args.first
          else
            raise SPKIError,
                  "Must pass String or OpenSSL::ASN1::Sequence (you gave me an instance of #{args.first.class})"
          end
        elsif args.length == 3
          alg_id, params, key_data = args
          alg_id = alg_id.is_a?(String) ? OpenSSL::ASN1::ObjectId.new(alg_id) : alg_id
          key_data = key_data.is_a?(String) ? OpenSSL::ASN1::BitString.new(key_data) : key_data

          alg_info = [alg_id, params].compact

          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::Sequence.new(alg_info),
            key_data
          ])
        else
          raise SPKIError,
                "SPKI.new takes either one or three arguments only"
        end

        validate_spki
      end

      # Return the DER-encoded SPKI structure.
      #
      # @return [String]
      #
      def to_der
        @spki.to_der
      end

      # Return an OpenSSL key.
      #
      # @return [OpenSSL::PKey::PKey]
      #
      def to_key
        OpenSSL::PKey.read(self.to_der)
      end

      # Return a digest object for the *public key* data.
      #
      # Some specifications (such as RFC5280's subjectKeyId) want a fingerprint
      # of only the key data, rather than a fingerprint of the entire SPKI
      # structure.  If so, this is the method for you.
      #
      # Because different things want their fingerprints in different formats,
      # this method returns a *digest object*, rather than a string, on which
      # you can call whatever output format method you like (`#digest`, `#hexdigest`,
      # or `#base64digest`, as appropriate).
      #
      # @param type [OpenSSL::Digest] override the default hash function used
      #   to calculate the digest.  The default, SHA1, is in line with the most
      #   common use of the key fingerprint, which is RFC5280 subjectKeyId
      #   calculation, however if you wish to use a different hash function
      #   you can pass an alternate digest class to use.
      #
      # @return [OpenSSL::Digest]
      #
      def key_fingerprint(type = OpenSSL::Digest::SHA1)
        type.new(@spki.value.last.value)
      end

      # Return a digest object for the entire DER-encoded SPKI structure.
      #
      # Some specifications (such as RFC7469 public key pins, and pwnedkeys.com
      # key IDs) require a hash of the entire DER-encoded SPKI structure.
      # If that's what you want, you're in the right place.
      #
      # Because different things want their fingerprints in different formats,
      # this method returns a *digest object*, rather than a string, on which
      # you can call whatever output format method you like (`#digest`, `#hexdigest`,
      # or `#base64digest`, as appropriate).
      #
      # @param type [OpenSSL::Digest] override the default hash function used
      # to calculate the digest.  The default, SHA256, is in line with the most
      # common uses of the SPKI fingerprint, however if you wish to use a
      # different hash function you can pass an alternate digest class to use.
      #
      # @return [OpenSSL::Digest]
      #
      def spki_fingerprint(type = OpenSSL::Digest::SHA256)
        type.new(@spki.to_der)
      end

      private

      def validate_spki
        unless @spki.is_a?(OpenSSL::ASN1::Sequence)
          raise SPKIError,
                "SPKI data is not an ASN1 sequence (got a #{@spki.class})"
        end

        if @spki.value.length != 2
          raise SPKIError,
                "SPKI top-level sequence must have two elements (length is #{@spki.value.length})"
        end

        alg_id, key_data = @spki.value

        unless alg_id.is_a?(OpenSSL::ASN1::Sequence)
          raise SPKIError,
                "SPKI algorithm_identifier must be a sequence (got a #{alg_id.class})"
        end

        unless (1..2) === alg_id.value.length
          raise SPKIError,
                "SPKI algorithm sequence must have one or two elements (got #{alg_id.value.length} elements)"
        end

        unless alg_id.value.first.is_a?(OpenSSL::ASN1::ObjectId)
          raise SPKIError,
                "SPKI algorithm identifier does not contain an object ID (got #{alg_id.value.first.class})"
        end

        unless key_data.is_a?(OpenSSL::ASN1::BitString)
          raise SPKIError,
                "SPKI publicKeyInfo field must be a BitString (got a #{@spki.value.last.class})"
        end
      end
    end
  end
end

require_relative "../pkey/rsa"
require_relative "../pkey/ec"
require_relative "./request"
require_relative "./certificate"
