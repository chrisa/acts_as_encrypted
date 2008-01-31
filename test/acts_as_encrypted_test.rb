require File.dirname(__FILE__) + '/test_helper'
require File.dirname(__FILE__) + '/test_helper_rails'

class ActsAsEncryptedTest < Test::Unit::TestCase

  def setup
    hostname = 'testhost'
    cryptoroot = File.expand_path(File.dirname(__FILE__) + "/keys")

    config = {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :filename             => "#{cryptoroot}/keystore",
      :initializing         => true
    }
    @ks = ActsAsEncrypted::Keystore.new(config)
    @ks.create_family('ccnum')
    f = @ks.family('ccnum')
    @ccnum_id = f.new_key(1)
    @ks.create_family('name')
    f = @ks.family('name')
    @name_id = f.new_key(1)
    @ks.save

    config.delete(:initializing)
    ActsAsEncrypted::Engine.engine = :local
    ActsAsEncrypted::Engine.config = config
    ActsAsEncrypted::Engine.reload
    
    test_root = File.expand_path(File.dirname(__FILE__))
    server_bin = "#{test_root}/../bin/encryption_server.rb"
    cryptoroot = "#{test_root}/keys"
    `#{server_bin} stop -- --hostname testhost --cryptoroot #{cryptoroot}`
    `#{server_bin} start -- --hostname testhost --cryptoroot #{cryptoroot}`
  end
    
  def teardown
    test_root = File.expand_path(File.dirname(__FILE__))
    server_bin = "#{test_root}/../bin/encryption_server.rb"
    cryptoroot = "#{test_root}/keys"
    `#{server_bin} stop -- --hostname testhost --cryptoroot #{cryptoroot}`

    RawCreditcard.find(:all).each do |rc|
      rc.destroy
    end
  end

  # test with the local engine
  def test_creditcard
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    name = "A N Other"
    type = "VISA"

    c.ccnum = ccnum
    c.cardholder = name
    c.cardtype = type
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
    assert_not_nil rc.ccnum_keyid
    assert_not_nil rc.name_keyid

    # reload from scratch
    fc = Creditcard.find(c.id)
    assert_equal ccnum, fc.ccnum
    assert_equal name, fc.cardholder
  end
  
  def test_no_key_family
    # run "encrypts :ccnum" in the context of NoKeyFamily
    # to trigger the configuration error.
    begin
      NoKeyFamily.class_eval do 
        encrypts :ccnum
      end
    rescue => e
      assert_equal ActsAsEncrypted::ConfigurationError, e.class
    else
      assert nil, "no exception raised"
    end
  end

  def test_default_key_only
    default = DefaultKeyFamily.new
    default.ccnum = '0000000000000000'
    default.cardtype = 'VISA'
    assert default.save
    assert_equal '0000000000000000', default.ccnum 

    rc = RawCreditcard.find(default.id)
    assert rc
    assert_not_equal rc.ccnum, default.ccnum
  end

  def test_tainting
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    name = "A N Other"
    type = "VISA"
    c.ccnum = ccnum
    c.cardholder = name
    c.cardtype = type
    assert c.save

    fc = Creditcard.find(c.id)
    assert_equal ccnum, fc.ccnum
    assert_equal name, fc.cardholder
  end

  def test_error_causes_validation_failure
    # Error engine always raises CryptoFailureError
    ActsAsEncrypted::Engine.engine = :error

    assert_equal 0, Creditcard.count

    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    name = "A N Other"
    type = "VISA"
    c.ccnum = ccnum
    c.cardholder = name
    c.cardtype = type

    assert_equal false, c.save
    assert_equal 1, c.errors.length
    assert_equal 0, Creditcard.count
  end

  def test_error_causes_validation_failure_with_real_validation
    # Error engine always raises CryptoFailureError
    ActsAsEncrypted::Engine.engine = :error

    assert_equal 0, Creditcard.count

    c = Creditcard.new
    assert c

    # Leave type out, generate extra validation error
    ccnum = "1234567812344523"
    name = "A N Other"
    c.ccnum = ccnum
    c.cardholder = name

    assert_equal false, c.save
    assert_equal 2, c.errors.length
    assert_equal 0, Creditcard.count
  end

  def test_try_encrypting_nil
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    type = "VISA"
    c.ccnum = ccnum
    c.cardtype = type
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

    name = "A N Other"
    ccnum = "1234567812344523"
    type = "VISA"
    c.ccnum = ccnum
    c.cardholder = name
    c.cardtype = type
    assert c.save
    engine1 = ActsAsEncrypted::Engine.engine.object_id

    c.ccnum = ccnum
    c.cardholder = name
    assert c.save
    engine2 = ActsAsEncrypted::Engine.engine.object_id

    ActsAsEncrypted::Engine.reload
    
    c.ccnum = ccnum
    c.cardholder = name
    assert c.save
    engine3 = ActsAsEncrypted::Engine.engine.object_id
    
    assert_equal engine1, engine2
    assert_not_equal engine1, engine3
  end    

  def test_key_rollover
    # save a credit card with the current key
    c = Creditcard.new
    assert c
    ccnum = "1234567812344523"
    name = "A N Other"
    type = "VISA"
    c.ccnum = ccnum
    c.cardholder = name
    c.cardtype = type
    assert c.save
    
    f = @ks.family('ccnum')
    f.new_key(Time.now.to_i + 1)
    f = @ks.family('name')
    f.new_key(Time.now.to_i + 1)
    @ks.save
    ActsAsEncrypted::Engine.reload
    
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
    cryptoroot = File.expand_path(File.dirname(__FILE__) + "/keys")
    hostname = 'testhost'
    config = {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER,
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}/#{hostname}_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}/cert_#{hostname}.pem")),
      :server               => 'localhost:3456'
    }    
    ActsAsEncrypted::Engine.engine = :remote
    ActsAsEncrypted::Engine.config = config
    
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    name = "A N Other"
    type = "VISA"
    c.ccnum = ccnum
    c.cardholder = name
    c.cardtype = type
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
