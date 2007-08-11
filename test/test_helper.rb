$:.push File.expand_path(File.dirname(__FILE__) + "/../lib")

require 'test/unit'
['/opt/local', '/usr/local'].each do |path|
  break if load "#{path}/bin/QuickCert"
end

CA = {}
CERTS = []

CA[:hostname] = 'testhost'
CA[:domainname] = 'testdomain'
CA[:CA_dir] = File.join Dir.pwd, "CA"
CA[:password] = '1234'

CERTS << {
  :type => 'server',
  :hostname => "testhost-server",
}

CERTS << {
  :type => 'client',
  :user => 'testhost',
  :email => 'aee@nodnol.org'
}

require 'QuickCert/defaults'

testdir = File.expand_path(File.dirname(__FILE__))
Dir.chdir(testdir) do 
  begin
    Dir.mkdir('keys')
    Dir.chdir('keys') do
      puts "creating CA"
      qc = QuickCert.new CA
      
      CERTS.each do |cert_config|
        puts "creating #{cert_config[:type]} cert"
        qc.create_cert cert_config
      end
    end
  rescue
    nil
  end
end

