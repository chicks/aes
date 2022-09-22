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
    
  should "handle padding option" do
    key = "01234567890123456789012345678901"
    msg = "This is a message that nobody should ever see"
    # unpadded message length should be a multiple of cipher block
    # length (16 bytes)
    msg += " "*(16 - (msg.length % 16))

    enc = AES.encrypt(msg, key, {:padding => false})
    assert_equal msg, AES.decrypt(enc, key, {:padding => false})
  end
  
  should "generate a new key when AES#key" do
    assert_equal 64, AES.key.length
    assert_equal 89, AES.key(256, :base_64).length
  end
    
end
