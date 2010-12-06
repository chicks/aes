require 'openssl'
require 'base64'

class AES
  class << self
    # Encrypts the plain_text with the provided key
    def encrypt(key, plain_text, opts={})
      AES.new(key,opts).encrypt(plain_text)
    end
    # Decrypts the cipher_text with the provided key
    def decrypt(key, cipher_text, opts={})
      AES.new(key,opts).decrypt(cipher_text)
    end
    # Generates a random key of the specified length in bits
    # Default output is 
    def key(length=256,format=:plain)
      key = AES.new("").random_key(256)
      case format
      when :base_64
        Base64.encode64(key)
      else
        key
      end
    end
  end

  attr :options
  attr :key
  attr :cipher
  attr :cipher_text
  attr :plain_text
  
  def initialize(key, opts={})
    merge_options opts
    @key = key
    self
  end
  
  # Encrypts
  def encrypt(plain_text)
    @plain_text = plain_text
    _setup(:encrypt)
    case @options[:format]
    when :base_64
      @cipher_text = b64_e(_iv) << "$" << b64_e(_encrypt)
    else
      @cipher_text = [_iv, _encrypt]
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
  def random_iv
    _setup(:encrypt)
    _iv
  end
  
  # Generate a random key
  def random_key(length=256)
    _random_seed.unpack('H*')[0][0..((length/8)-1)]
    #Digest::SHA256.digest(_random_seed)[0..(length / 8)]
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
      iv_ctext = []
      data.split('$').each do |part|
        iv_ctext << Base64.decode64(part)
      end
      iv_ctext
    end
  
    # Base64 Encodes a string
    def b64_e(data)
      Base64.encode64(data).chomp
    end
  
    # Generates and returns a random initialization vector
    def _iv
      @cipher.random_iv
    end
    
    # Encrypts @plain_text
    def _encrypt
      @cipher.update(@plain_text) + @cipher.final
    end

    # Merge init options with defaults
    def merge_options(opts)
      @options = {
        :format => :base_64,
        :cipher => "AES-256-CBC"
      }.merge! opts
    end
      
    # Create a new cipher using the cipher type specified
    def _setup(action)
      @cipher = OpenSSL::Cipher::Cipher.new(@options[:cipher]) 
      # Toggles encryption mode
      @cipher.send(action)
      @cipher.key = @key.unpack('a2'*32).map{|x| x.hex}.pack('c'*32)  
    end
end