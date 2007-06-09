module ActsAsEncrypted
  class KeyStore

    def initialize(config)
      @config = config
      if @config[:initializing]
        @config.delete(:initializing)
        return init_keystore
      end

      ciphertext = File.read(@config[:filename])
      ksdata = @config[:SSLPrivateKey].private_decrypt(ciphertext)
      return ksdata
    end

    def get_current_key(family)
      # TODO. 
      return "\203\306\226:\253\026J:\236\306r\355$\326V\370\232\357\252w6\006;\265\032J\272\240\222\342\256\325"
    end

    private
    def init_keystore
      ksdata = Marshal.dump({})
      public_rsa = @config[:SSLPrivateKey].public_key
      ciphertext = public_rsa.public_encrypt(ksdata)
      File.open(@config[:filename],  "w+") { |fp| fp << ciphertext }
      ksdata
    end

  end
end
