require "openssl"

module OpenSSL
  module PKey
    SSH_CURVE_NAME_MAP = {
      "nistp256" => "prime256v1",
      "nistp384" => "secp384r1",
      "nistp521" => "secp521r1",
    }

    def self.from_ssh_key(s)
      if s =~ /\Assh-[a-z0-9-]+ /
        # WHOOP WHOOP prefixed key detected.
        s = s.split(" ")[1]
      else
        # Discard any comment, etc that might be lurking around
        s = s.split(" ")[0]
      end

      unless s =~ /\A[A-Za-z0-9\/+]+={0,2}\z/
        raise OpenSSL::PKey::PKeyError,
              "Invalid key encoding (not valid base64)"
      end

      parts = ssh_key_lv_decode(s)

      case parts.first
      when "ssh-rsa"
        OpenSSL::PKey::RSA.new.tap do |k|
          k.e = ssh_key_mpi_decode(parts[1])
          k.n = ssh_key_mpi_decode(parts[2])
        end
      when "ssh-dss"
        OpenSSL::PKey::DSA.new.tap do |k|
          k.p = ssh_key_mpi_decode(parts[1])
          k.q = ssh_key_mpi_decode(parts[2])
          k.g = ssh_key_mpi_decode(parts[3])
        end
      when /ecdsa-sha2-/
        begin
          OpenSSL::PKey::EC.new(SSH_CURVE_NAME_MAP[parts[1]]).tap do |k|
            k.public_key = OpenSSL::PKey::EC::Point.new(k.group, parts[2])
          end
        rescue TypeError
          raise OpenSSL::PKey::PKeyError.new,
                "Unknown curve identifier #{parts[1]}"
        end
      else
        raise OpenSSL::PKey::PKeyError,
              "Unknown key type #{parts.first.inspect}"
      end
    end

    private

    def self.ssh_key_lv_decode(s)
      rest = s.unpack("m").first

      [].tap do |parts|
        until rest == ""
          len, rest = rest.unpack("Na*")
          if len > rest.length
            raise OpenSSL::PKey::PKeyError,
                  "Invalid LV-encoded string; wanted #{len} octets, but there's only #{rest.length} octets left"
          end

          elem, rest = rest.unpack("a#{len}a*")
          parts << elem
        end
      end
    end

    def self.ssh_key_mpi_decode(s)
      s.each_char.inject(0) { |i, c| i * 256 + c.ord }
    end
  end
end
