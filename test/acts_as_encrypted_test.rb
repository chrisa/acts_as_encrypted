require File.dirname(__FILE__) + '/test_helper'
require File.dirname(__FILE__) + '/test_helper_rails'

class ActsAsEncryptedTest < Test::Unit::TestCase

  def setup
     server_bin = File.expand_path(File.dirname(__FILE__) + "/../bin/server.rb")
    `#{server_bin} start`
  end
    
  def teardown
     server_bin = File.expand_path(File.dirname(__FILE__) + "/../bin/server.rb")
    `#{server_bin} stop`    
  end

  # test with the local engine
  def test_creditcard
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    name = "A N Other"

    c.ccnum = ccnum
    c.cardholder = name
    assert c.save

    assert_equal "4523", c.ccnum_lastfour
    assert_equal ccnum, c.ccnum
    assert_equal name, c.cardholder
    assert c.ccnum_iv
    assert c.cardholder_iv

    rc = RawCreditcard.find(c.id)
    assert rc

    assert_equal rc.ccnum_iv, c.ccnum_iv
    assert_equal rc.cardholder_iv, c.cardholder_iv
    assert_equal rc.ccnum_lastfour, c.ccnum_lastfour
    assert_not_equal rc.ccnum, c.ccnum
    assert_not_equal rc.cardholder, c.cardholder
  end

  def test_try_encrypting_nil
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    c.ccnum = ccnum
    assert c.save

    assert_equal "4523", c.ccnum_lastfour
    assert_equal ccnum, c.ccnum
    assert c.ccnum_iv
    assert_nil c.cardholder
    assert_nil c.cardholder_iv
  end
  
  # test with the remote engine
  def test_creditcard_remote
    cryptoroot = File.expand_path(File.dirname(__FILE__) + "/../keys")
    full_hostname = `hostname`.strip
    hostname = full_hostname.split('.')[0]
    config = {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER,
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}/#{hostname}_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}/cert_#{hostname}.pem")),
      :server               => 'localhost:3456'
    }    
    ActsAsEncrypted::Engine.engine = 'remote'
    ActsAsEncrypted::Engine.config = config
    
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    name = "A N Other"
    c.ccnum = ccnum
    c.cardholder = name
    assert c.save

    assert_equal "4523", c.ccnum_lastfour
    assert_equal ccnum, c.ccnum
    assert_equal name, c.cardholder
    assert c.ccnum_iv
    assert c.cardholder_iv

    rc = RawCreditcard.find(c.id)
    assert rc

    assert_equal rc.ccnum_iv, c.ccnum_iv
    assert_equal rc.cardholder_iv, c.cardholder_iv
    assert_equal rc.ccnum_lastfour, c.ccnum_lastfour
    assert_not_equal rc.ccnum, c.ccnum
    assert_not_equal rc.cardholder, c.cardholder
  end

end
