RAILS_ENV = 'test'
require File.expand_path(File.join(File.dirname(__FILE__), '../../../../config/environment.rb'))
require 'test/unit'

class ActsAsEncryptedTest < Test::Unit::TestCase
  def test_creditcard
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    
    c.ccnum = ccnum
    assert c.save

    assert_equal "4523", c.ccnum_lastfour
    assert_equal ccnum, c.ccnum
    assert c.ccnum_iv
  end
end
