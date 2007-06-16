require 'drb'
require 'drb/ssl'
require 'acts_as_encrypted/engine'

module ActsAsEncrypted
  class Server
    def initialize(config)
      @config = config
      @engine = ActsAsEncrypted::Engine::Local.new(@config)
    end

    def api
      Server::API.new(@engine)
    end

    def run
      here = "drbssl://#{@config[:server]}"
      DRb.start_service here, api, @config
      DRb.thread.join
    end
    
  end

  class Server::API
    def initialize(engine)
      @engine = engine
    end
    
    def ping
      "ok"
    end
    
    def encrypt(family, plaintext)
      puts "server encrypt"
      @engine.encrypt(family, plaintext)
    end

    def decrypt(family, iv, ciphertext)
      puts "server decrypt"
      @engine.decrypt(family, iv, ciphertext)
    end

  end
end
