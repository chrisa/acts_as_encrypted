namespace :acts_as_encrypted do

  desc 'Set up acts_as_encrypted in your rails application'
  task :setup do
    ['keytool', 'encryption_server'].each do |script|
      script_dest = "#{RAILS_ROOT}/script/#{script}"
      script_src = File.dirname(__FILE__) + "/../bin/#{script}.rb"
      
      FileUtils.chmod 0774, script_src
      
      unless File.exists?(script_dest)
        puts "Copying acts_as_encrypted script #{script}.rb to #{script_dest}"
        FileUtils.cp_r(script_src, script_dest)
      end
    end
  end
  
  desc 'Remote acts_as_encrypted from your rails application'
  task :remove do 
    ['keytool', 'encryption_server'].each do |script|
      script_src = "#{RAILS_ROOT}/script/#{script}"

      if File.exists?(script_src)
        puts "Removing #{script_src} ..."
        FileUtils.rm(script_src, :force => true)
      end
    end
  end

end
    
