require 'helper'

class TestAES < Test::Unit::TestCase
    
  should "encrypt and decrypt a string" do
    key = "01234567890123456789012345678901"
    msg = "This is a message that nobody should ever see"
    enc = AES.encrypt(key, msg)
    assert_equal msg, AES.decrypt(key, enc)
    enc = AES.encrypt(key, msg, {:format => :plain})
    assert_equal msg, AES.decrypt(key, enc, {:format => :plain})
  end
  
  should "generate a new key when AES#key" do
    assert_equal 32, AES.key.length
    assert_equal 45, AES.key(256, :base_64).length
  end
    
end
