require File.dirname(__FILE__) + '/test_helper'

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

    rc = RawCreditcard.find(c.id)
    assert rc

    assert_equal rc.ccnum_iv, c.ccnum_iv
    assert_equal rc.ccnum_lastfour, c.ccnum_lastfour
    assert_not_equal rc.ccnum, c.ccnum
  end

  def test_creditcard_remote
    cryptoroot = File.expand_path(File.dirname(__FILE__) + "/../keys")
    full_hostname = `hostname`.strip
    hostname = full_hostname.split('.')[0]
    config = {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER,
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}/#{hostname}_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}/cert_#{hostname}.pem")),
    }    
    ActsAsEncrypted::Engine.engine = 'remote'
    ActsAsEncrypted::Engine.config = config
    
    c = Creditcard.new
    assert c

    ccnum = "1234567812344523"
    c.ccnum = ccnum
    assert c.save

    assert_equal "4523", c.ccnum_lastfour
    assert_equal ccnum, c.ccnum
    assert c.ccnum_iv

    rc = RawCreditcard.find(c.id)
    assert rc

    assert_equal rc.ccnum_iv, c.ccnum_iv
    assert_equal rc.ccnum_lastfour, c.ccnum_lastfour
    assert_not_equal rc.ccnum, c.ccnum    
  end

  def test_init_keystore 
    config = get_config
    config[:initializing] = true
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
  end

  def test_new_family
    config = get_config
    config[:initializing] = true
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
    
    f = ks.families
    assert_equal 0, f.length

    ks.create_family('foo')
    f = ks.families
    assert_equal 1, f.length
    assert_equal 'foo', f.first
  end

  def test_new_key
    config = get_config
    config[:initializing] = true
    ks = ActsAsEncrypted::Keystore.new(config)
    assert ks
    ks.create_family('foo')
    ks.new_key('foo', Time.now)
  end

  private 
  def get_config
    cryptoroot = File.expand_path(File.join(File.dirname(__FILE__),'keys'))
    {
      :SSLVerifyMode        => OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
      :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.read("#{cryptoroot}/#{hostname}-server/#{hostname}-server_keypair.pem")),
      :SSLCertificate       => OpenSSL::X509::Certificate.new(File.read("#{cryptoroot}/#{hostname}-server/cert_#{hostname}-server.pem")),
      :SSLCACertificateFile => "#{cryptoroot}/CA/cacert.pem",
      :filename             => "#{cryptoroot}/keystore"
    }
  end
end
