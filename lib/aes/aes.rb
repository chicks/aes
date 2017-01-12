module AES
  DEFAULT_AES_CIPHER = "AES-256-CBC"

  class << self
    # Encrypts the plain_text with the provided key
    def encrypt(plain_text, key, opts={})
      ::AES::AES.new(key, opts).encrypt(plain_text)
    end
    # Decrypts the cipher_text with the provided key
    def decrypt(cipher_text, key, opts={})
      ::AES::AES.new(key, opts).decrypt(cipher_text)
    end
    # Generates a random key of the specified length in bits
    # Default format is :plain
    def key(length=256,format=:plain)
      key = ::AES::AES.new("").random_key(length)
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
      cipher = OpenSSL::Cipher::Cipher.new(DEFAULT_AES_CIPHER)
      cipher.encrypt
      iv = cipher.random_iv
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
  
    def initialize(key, opts={})
      merge_options opts
      @cipher = nil
      @key    = key
      @iv   ||= ::AES.iv
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

    # Generate a random initialization vector
    # There's no reason to call random_iv on an instance
    # This has been left for backwards compatibility,
    # but it now just delegates to the class method
    def random_iv
      ::AES.iv(@options[:format])
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
          :format  => :base_64,
          :cipher  => ::AES::DEFAULT_AES_CIPHER,
          :iv      => nil,
          :padding => true, # use cipher padding by default
        }.merge! opts
        _handle_iv
        _handle_padding
      end
      
      def _handle_iv
        @iv = @options[:iv]
        return if @iv.nil?

        case @options[:format]
        when :base_64
          @iv  = Base64.decode64(@options[:iv])
        end
      end
      
      def _handle_padding
        # convert value to what OpenSSL module format expects
        @options[:padding] = @options[:padding] ? 1 : 0
      end
      
      # Create a new cipher using the cipher type specified
      def _setup(action)
        @cipher ||= OpenSSL::Cipher::Cipher.new(@options[:cipher]) 
        # Toggles encryption mode
        @cipher.send(action)
        @cipher.padding = @options[:padding]
        @cipher.key = @key.unpack('a2'*32).map{|x| x.hex}.pack('c'*32)
      end
  end
end
