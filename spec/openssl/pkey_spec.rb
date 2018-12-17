require_relative "../spec_helper"

require "openssl/pkey"

describe OpenSSL::PKey do
  describe "#from_ssh_key" do
    let(:pkey) { OpenSSL::PKey.from_ssh_key(ssh_key) }

    context "given an RSA key with a prefix" do
      let(:ssh_key) do
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCZI+gzukzJkpokvvIIpVkh2K0G2gDv" +
        "JKBjnj4nDzkOqbqQrNxZ+MNJy5/z4HcA2Mbi8hcKJMUWJW/JMrwTzm8jDkDvYITdsy22" +
        "60m0Up84ySlFlgGwB73jZuGnrf6Lbe2X9+P5H3h/3JpJ0+OxoRjqWYerKaWJF/wVFlqe" +
        "bYl8bw=="
      end

      it "returns an RSA key" do
        expect(pkey).to be_an(OpenSSL::PKey::RSA)
      end

      it "returns the *correct* RSA key" do
        expect(pkey.e).to eq(65537)
      end
    end

    context "given an RSA key without a prefix" do
      let(:ssh_key) do
        "AAAAB3NzaC1yc2EAAAADAQABAAAAgQCZI+gzukzJkpokvvIIpVkh2K0G2gDvJKBjnj4n" +
        "DzkOqbqQrNxZ+MNJy5/z4HcA2Mbi8hcKJMUWJW/JMrwTzm8jDkDvYITdsy2260m0Up84" +
        "ySlFlgGwB73jZuGnrf6Lbe2X9+P5H3h/3JpJ0+OxoRjqWYerKaWJF/wVFlqebYl8bw==" +
        " arglefargle"
      end

      it "returns an RSA key" do
        expect(pkey).to be_an(OpenSSL::PKey::RSA)
      end

      it "returns the *correct* RSA key" do
        expect(pkey.e).to eq(65537)
      end
    end

    context "given a DSA key" do
      let(:ssh_key) do
        # Wow I'd forgotten how huge DSS keys are...
        "AAAAB3NzaC1kc3MAAACBAM6PC9FHvwGP8i5XC650aQEFOefh3PA9/OuAi5YeJ2xL02FA" +
        "04uaceUKcjecr5zKktmPDGSK9YbsmHcMUazTuEXu6GGguR08YfD12AtKDcS/7DDFHZtM" +
        "Dfy4ZovuOuk3NB76205swbUsBi6qElfKFgJ+e591MqgycDm0wYnasntVAAAAFQDQOURk" +
        "LrRktUEsJlMdKMVy53SSRwAAAIEAvdzwLbh/cMHz92cOodF6TSZKiEAX5qtKgWyL+zKX" +
        "nS3vbrcI1Y5alMb2VRSNm1dYEX4CY/XdsO+4Sxyv0CpXWf391bW0b+vE6vj660+yoGwe" +
        "HcebuPDpCr6xckWdlwuL9NIxvStB8pkMJ+9Xb9RVJYALAcIM3h0NVOvaRp70iSYAAACA" +
        "eHdzuTojgJSc0zjGqER/mfMWS3Id+H7JmwFIGBw1oaVDoBN8OlE+QHxaMSR2Vwo8smmp" +
        "aZ9KQfsOEE4f0y+9+H+mysJEQQzdYLYW6jjQEs1VSbLwgyZiWQyghtx4IMvcYjy1Ou7L" +
        "+dgTkCETBY43OhxOsyxFB9EIWdW4rZsvIEE="
      end

      it "returns a DSA key" do
        expect(pkey).to be_an(OpenSSL::PKey::DSA)
      end
    end

    context "given a P-256 EC key" do
      let(:ssh_key) do
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP8bNZ1mT+YVRO5k" +
        "OGtyvhIgfV/WgpuLE8znAxYdXcBxyrl3wJH4gW0ynwiwiDRwC6PwPfiAqUvt4oJ/2AXR" +
        "Ei0="
      end

      it "returns an EC key" do
        expect(pkey).to be_an(OpenSSL::PKey::EC)
      end

      it "returns the right curve" do
        expect(pkey.group.curve_name).to eq("prime256v1")
      end

      it "returns a valid public key" do
        expect(pkey).to be_public
      end
    end

    context "given a P-384 EC key" do
      let(:ssh_key) do
        "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBBat9t51O7ISnZP" +
        "8fyOpC/EjxYaqxeAinUolYXihvfLKwylHiZCscziD2/A4Cl/0F7sKjsQcYSJxJPM73D4" +
        "4sVP5yjSytpm6GZNAUlbGIL2J/HOo3afITbk60uWmMxVpw=="
      end

      it "returns an EC key" do
        expect(pkey).to be_an(OpenSSL::PKey::EC)
      end

      it "returns the right curve" do
        expect(pkey.group.curve_name).to eq("secp384r1")
      end

      it "returns a valid public key" do
        expect(pkey).to be_public
      end
    end

    context "given a P-521 EC key" do
      let(:ssh_key) do
        "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHFtMbDFx9QH+qQ" +
        "014JZSI8VyfTPe1XKj23w6IorpOikQEETSuBsIGF4fMoP4xrLU6II8w2qi50F2xwPHNh" +
        "2v9xtgBJO0aNKv06igUD1fDeNgrl34feCd6IsIRVKyjt493tYl0jd5YzYPEh2gnT/xPd" +
        "g2aQHcPjtx3qwWOm7C2UkJGmMw=="
      end

      it "returns an EC key" do
        expect(pkey).to be_an(OpenSSL::PKey::EC)
      end

      it "returns the right curve" do
        expect(pkey.group.curve_name).to eq("secp521r1")
      end

      it "returns a valid public key" do
        expect(pkey).to be_public
      end
    end

    context "given a mystery curve EC key" do
      let(:ssh_key) do
        ["\x00\x00\x00\x13ecdsa-sha2-nistp666" +
         "\x00\x00\x00\x08nistp666" +
         "\x00\x00\x00\x05ohai!"].pack("m")
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /nistp666/)
      end
    end

    context "given a key of some mystery type" do
      let(:ssh_key) do
        ["\x00\x00\x00\x0Assh-lolrus\x00\x00\x00\x05ohai!"].pack("m")
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /ssh-lolrus/)
      end
    end

    context "given a key that isn't valid base64" do
      let(:ssh_key) { "notbase64!!!" }

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError)
      end
    end

    context "given a LV stanza with an out-of-bounds length" do
      let(:ssh_key) do
        ["\x00\x00\x00\xFFthis isn't 256 characters long!"].pack("m")
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError)
      end
    end
  end
end
