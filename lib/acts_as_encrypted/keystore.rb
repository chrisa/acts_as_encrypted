require 'openssl'

module ActsAsEncrypted
  class Keystore

    def initialize(config)
      @config = config
      if @config[:initializing]
        @config.delete(:initializing)
        ksdata = init_keystore
      else
        ciphertext = File.read(@config[:filename])
        ksdata = @config[:SSLPrivateKey].private_decrypt(ciphertext)
      end
      @ks = Marshal.restore(ksdata)
    end

    def get_current_key(family)
      unless @ks[:family]
        raise "empty keystore?"
      end
      unless @ks[:family][family.to_s]
        raise "no family #{family}"
      end
      valid = @ks[:family][family.to_s].keys.select do |t|
        t <= Time.now
      end
      @ks[:family][family.to_s][valid.sort.first]
    end

    def each_family
      @ks[:family].each do |k,v|
        yield k
      end
    end

    def families
      @ks[:family].keys
    end

    def new_key(f, start)
      k = OpenSSL::Random.random_bytes(32)
      @ks[:family][f][start] = k
    end

    def create_family(f)
      @ks[:family][f] = Hash.new
    end

    def save
      write_keystore(Marshal.dump(@ks))
    end
    
    def init_keystore
      ks = Hash.new
      ks[:serial] = 0
      ks[:family] = Hash.new
      write_keystore(Marshal.dump(ks))
    end

    protected
    def command_missing
    end
    
    private
    def write_keystore(ksdata)
      public_rsa = @config[:SSLPrivateKey].public_key
      ciphertext = public_rsa.public_encrypt(ksdata)
      File.open(@config[:filename],  "w") { |fp| fp << ciphertext }
      ksdata
    end
    
  end
end
