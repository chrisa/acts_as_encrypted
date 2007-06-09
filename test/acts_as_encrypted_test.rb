RAILS_ENV = 'test'
require File.expand_path(File.join(File.dirname(__FILE__), '../../../../config/environment.rb'))
require 'test/unit'

class ActsAsEncryptedTest < Test::Unit::TestCase
  def test_creditcard
    c = Creditcard.new
    assert c
    
    c.ccnum = "123456781234abcd"
    assert c.save

    p c

    assert_equal "abcd", c.ccnum_lastfour
  end
end
