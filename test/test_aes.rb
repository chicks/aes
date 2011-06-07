require 'helper'

class TestAES < Test::Unit::TestCase

  should "encrypt and decrypt a string" do
    key = "01234567890123456789012345678901"
    msg = "This is a message that nobody should ever see"
    enc = AES.encrypt(msg, key)
    assert_equal msg, AES.decrypt(enc, key)
    enc = AES.encrypt(msg, key, {:format => :plain})
    assert_equal msg, AES.decrypt(enc, key, {:format => :plain})
  end

  should "produce the same encrypted string when provided an identical key and iv" do
    key  = "01234567890123456789012345678901"
    msg  = "This is a message that nobody should ever see"
    iv   = AES.iv(:base_64)
    enc1 = AES.encrypt(msg, key, {:iv => iv})
    enc2 = AES.encrypt(msg, key, {:iv => iv})
    assert_equal enc1, enc2
  end

  should "generate a new key when AES#key" do
    assert_equal 32, AES.key.length
    assert_equal 44, AES.key(256, :base_64).length
  end

  should "encrypt and decrypt a file" do
    key = "01234567890123456789012345678901"
    msg = "This is a message that nobody should ever see"
    File.open('message.txt', 'w') { |f| f.write(msg) }

    AES.encrypt_file('message.txt', 'encrypted.txt', key)
    assert_not_equal(File.read('message.txt'), File.read('encrypted.txt'))

    AES.decrypt_file('encrypted.txt', 'decrypted.txt', key)
    assert_equal(File.read('message.txt'), File.read('decrypted.txt'))

  end

  def teardown
    files = ['message.txt', 'encrypted.txt', 'decrypted.txt']
    files.each do |file|
      if File.exists?(file)
        File.delete(file)
      end
    end
  end

end
