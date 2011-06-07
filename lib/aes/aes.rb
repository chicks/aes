module AES
  class << self
    # Encrypts the plain_text with the provided key
    def encrypt(plain_text, key, opts={})
      ::AES::AES.new(key, opts).encrypt(plain_text)
    end

    # Encrypts an file
    def encrypt_file(filepath, enc_filepath, key, opts={})
      ::AES::AES.new(key, opts).encrypt_file(filepath, enc_filepath)
    end

    # Decrypts the cipher_text with the provided key
    def decrypt(cipher_text, key, opts={})
      ::AES::AES.new(key, opts).decrypt(cipher_text)
    end

    # Decrypts an file
    def decrypt_file(filepath, enc_filepath, key, opts={})
      ::AES::AES.new(key, opts).decrypt_file(filepath, enc_filepath)
    end

    # Generates a random key of the specified length in bits
    # Default format is :plain
    def key(length=256,format=:plain)
      key = ::AES::AES.new("").random_key(256)
      case format
      when :base_64
        Base64.encode64(key).chomp
      else
        key
      end
    end
    # Generates a random iv
    # Default format is :plain
    def iv(format=:plain)
      iv = ::AES::AES.new("").random_iv
      case format
      when :base_64
        Base64.encode64(iv).chomp
      else
        iv
      end
    end
  end

  class AES
    attr :options
    attr :key
    attr :iv
    attr :cipher
    attr :cipher_text
    attr :plain_text

    ENCRYPT_CHUNK_SIZE = 2048
    DECRYPT_CHUNK_SIZE = 2822 #it uses base64 on the encrypted chunk. this is the size after the base64 encoding.

    def initialize(key, opts={})
      merge_options opts
      @cipher = nil
      @key    = key
      @iv   ||= random_iv
      self
    end

    # Encrypts
    def encrypt(plain_text)
      @plain_text = plain_text
      _setup(:encrypt)
      @cipher.iv  = @iv
      case @options[:format]
      when :base_64
        @cipher_text = b64_e(@iv) << "$" << b64_e(_encrypt)
      else
        @cipher_text = [@iv, _encrypt]
      end
      @cipher_text
    end

    def encrypt_file(filepath, encrypted_filepath)
      enc_file = File.open(encrypted_filepath, 'wb')
      File.open(filepath, 'rb') do |f|
        until f.eof
          chunk = f.read(ENCRYPT_CHUNK_SIZE)
          enc_file.write(encrypt(chunk))
        end
      end
      enc_file.close
    end

    # Decrypts
    def decrypt(cipher_text)
      @cipher_text = cipher_text
      _setup(:decrypt)
      case @options[:format]
      when :base_64
        ctext = b64_d(@cipher_text)
      else
        ctext = @cipher_text
      end
      @cipher.iv  = ctext[0]
      @plain_text = @cipher.update(ctext[1]) + @cipher.final
    end

    def decrypt_file(encrypted_filepath, filepath)
      file = File.open(filepath, 'wb')
      File.open(encrypted_filepath, 'rb') do |f|
        until f.eof
          chunk = f.read(DECRYPT_CHUNK_SIZE)
          file.write(decrypt(chunk))
        end
      end
      file.close
    end

    # Generate a random initialization vector
    def random_iv
      _setup(:encrypt)
      @cipher.random_iv
    end

    # Generate a random key
    def random_key(length=256)
      _random_seed.unpack('H*')[0][0..((length/8)-1)]
    end

    private

      # Generates a random seed value
      def _random_seed(size=32)
        if defined? OpenSSL::Random
          return OpenSSL::Random.random_bytes(size)
        else
          chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
          (1..size).collect{|a| chars[rand(chars.size)] }.join
        end
      end

      # Un-Base64's the IV and CipherText
      # Returns an array containing the IV, and CipherText
      def b64_d(data)
        iv_and_ctext = []
        data.split('$').each do |part|
          iv_and_ctext << Base64.decode64(part)
        end
        iv_and_ctext
      end

      # Base64 Encodes a string
      def b64_e(data)
        Base64.encode64(data).chomp
      end

      # Encrypts @plain_text
      def _encrypt
        @cipher.update(@plain_text) + @cipher.final
      end

      # Merge init options with defaults
      def merge_options(opts)
        @options = {
          :format => :base_64,
          :cipher => "AES-256-CBC",
          :iv     => nil,
        }.merge! opts
        _handle_iv
      end

      def _handle_iv
        @iv = @options[:iv]
        return if @iv.nil?

        case @options[:format]
        when :base_64
          @iv  = Base64.decode64(@options[:iv])
        end
      end

      # Create a new cipher using the cipher type specified
      def _setup(action)
        @cipher ||= OpenSSL::Cipher::Cipher.new(@options[:cipher])
        # Toggles encryption mode
        @cipher.send(action)
        @cipher.key = @key.unpack('a2'*32).map{|x| x.hex}.pack('c'*32)
      end
  end
end
