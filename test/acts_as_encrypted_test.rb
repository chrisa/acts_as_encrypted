require File.dirname(__FILE__) + '/test_helper'
require File.dirname(__FILE__) + '/test_helper_rails'

class ActsAsEncryptedTest < Test::Unit::TestCase

  def setup
    full_hostname = `hostname`.strip
    hostname = full_hostname.split('.')[0]
    cryptoroot = File.expand_path(File.dirname(__FILE__) + "/../keys")
    config = {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :filename             => "#{cryptoroot}/keystore",
      :initializing         => true
    }
    ks = ActsAsEncrypted::Keystore.new(config)
    ks.create_family('ccnum')
    ks.new_key('ccnum', Time.now)
    ks.create_family('name')
    ks.new_key('name', Time.now)
    ks.save
    
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
    assert_equal 'A', c.cardholder_initial
    assert c.ccnum_iv
    assert c.cardholder_iv

    rc = RawCreditcard.find(c.id)
    assert rc
    
    assert_equal rc.ccnum_iv, c.ccnum_iv
    assert_equal rc.cardholder_iv, c.cardholder_iv
    assert_equal rc.ccnum_lastfour, c.ccnum_lastfour
    assert_equal rc.cardholder_initial, c.cardholder_initial
    assert_not_equal rc.ccnum, c.ccnum
    assert_not_equal rc.cardholder, c.cardholder
    assert_not_nil rc.ccnum_start
    assert_not_nil rc.name_start

    # reload from scratch
    fc = Creditcard.find(c.id)
    assert_equal ccnum, fc.ccnum
    assert_equal name, fc.cardholder
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

  def test_multiple_ops
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    c.ccnum = ccnum
    assert c.save
    engine1 = ActsAsEncrypted::Engine.engine.object_id

    ccnum = "1234567812344524"
    c.ccnum = ccnum
    assert c.save
    engine2 = ActsAsEncrypted::Engine.engine.object_id

    ActsAsEncrypted::Engine.reload
    
    ccnum = "1234567812344525"
    c.ccnum = ccnum
    assert c.save
    engine3 = ActsAsEncrypted::Engine.engine.object_id
    
    assert_equal engine1, engine2
    assert_not_equal engine1, engine3
  end    

  def test_key_rollover
    # set up a new keystore and configure AEE to use it
    cryptoroot = File.expand_path(File.dirname(__FILE__) + "/keys")
    config = {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/testhost-server/testhost-server_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/testhost-server/cert_testhost-server.pem")),
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :filename             => "#{cryptoroot}/keystore_for_rollover_test",
      :initializing         => true
    }
    ks = ActsAsEncrypted::Keystore.new(config)
    ks.create_family('ccnum')
    ks.new_key('ccnum', Time.now)
    ks.create_family('name')
    ks.new_key('name', Time.now)
    ks.save
    ActsAsEncrypted::Engine.engine = 'local'
    ActsAsEncrypted::Engine.config = config
    
    # save a credit card with the current key
    c = Creditcard.new
    assert c
    ccnum = "1234567812344523"
    name = "A N Other"
    c.ccnum = ccnum
    c.cardholder = name
    assert c.save
    
    # generate a couple of new keys - don't reinit keystore!
    config.delete(:initializing)
    ks = ActsAsEncrypted::Keystore.new(config)
    sleep 2 # get a tick to make sure new key has different time
    ks.new_key('ccnum', Time.now)
    ks.new_key('name', Time.now)
    ks.save
    
    # check the raw row is there
    rc = RawCreditcard.find(c.id)
    assert rc

    # check we can decrypt with the old key
    fc = Creditcard.find(c.id)
    assert_equal ccnum, fc.ccnum
    assert_equal name, fc.cardholder

    # reencrypt with the current key
    fc.reencrypt
    fc.save

    fc = Creditcard.find(c.id)
    assert_equal ccnum, fc.ccnum
    assert_equal name, fc.cardholder
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
    assert_equal 'A', c.cardholder_initial
    assert c.ccnum_iv
    assert c.cardholder_iv

    rc = RawCreditcard.find(c.id)
    assert rc

    assert_equal rc.ccnum_iv, c.ccnum_iv
    assert_equal rc.cardholder_iv, c.cardholder_iv
    assert_equal rc.ccnum_lastfour, c.ccnum_lastfour
    assert_equal rc.cardholder_initial, c.cardholder_initial
    assert_not_equal rc.ccnum, c.ccnum
    assert_not_equal rc.cardholder, c.cardholder
  end

end
