$: << File.dirname(__FILE__)
require "certificate_authority_cli/version"
require 'certificate_authority'
require 'thor'
require 'yaml'
require 'logger'
require 'highline/import'

Log = Logger.new(STDOUT)

GENERIC_SUBJECT = {"cn" => "", "ou" => ""}
NEW_ROOT_SETTINGS = {"subject" => GENERIC_SUBJECT, "modulus" => 2048, "cert_file" => "/tmp/ca.crt", "key_file" => "/tmp/ca.key"}

module CertificateAuthorityCli
  def self.get_password(prompt="Enter Password")
    ask(prompt) {|q| q.echo = false}
  end

  class Config
    attr_accessor :signing_cert
    attr_accessor :signing_key
    attr_accessor :signing_password
    attr_accessor :signing_profile
    attr_accessor :command_specific

    def self.from_yaml(yaml)
      conf = Config.new
      data = YAML.load(yaml)
      if data.is_a?(Config)
        return data
      end
      puts data
      data.each do |k,v|
        sym = "#{k}=".to_sym
        if conf.respond_to?(sym)
          conf.send(sym,v)
          Log.info "Config: #{k} = #{v}"
        else
          Log.error "Unknown key in config (#{k}=#{v})"
        end
      end
      conf
    end
  end

  class Cli < Thor
    desc "generate_root", "Generate a new root on disk"
    def generate_root
      Log.info "Generating root"
      editor = Editor.new()
      on_change = lambda { |new_content|
        settings = YAML.load(new_content)

        root = CertificateAuthority::Certificate.new
        root.subject.common_name= settings["subject"]["cn"]
        root.serial_number.number=1
        root.key_material.generate_key(settings["modulus"])
        root.signing_entity = true
        signing_profile = {"extensions" => {"keyUsage" => {"usage" => ["critical", "keyCertSign"] }} }
        root_cert = root.sign!(signing_profile)

        password = CertificateAuthorityCli.get_password("Enter a root password (blank for none)")
        if password.empty?
          private_output = root.key_material.private_key.to_pem
        else
          cipher = OpenSSL::Cipher.new('AES-256-CBC')
          private_output = root.key_material.private_key.to_pem(cipher,password)
        end

        Log.info "Writing root certificate to #{settings["cert_file"]}"
        Log.info "Writing root private key to #{settings["key_file"]}"
        File.open(settings["cert_file"], 'w') {|f| f.write(root_cert.to_pem) }
        File.open(settings["key_file"], 'w') {|f| f.write(private_output) }
      }

      editor.edit!(NEW_ROOT_SETTINGS.to_yaml,on_change)
    end

    desc "show_csr", "Print CSR data"
    def show_csr(csr_path)
      ## Just use OpenSSL for this
      exec("openssl req -in #{csr_path} -text")
    end

    desc "sign_csr [CONFIG] [CSR_PATH]", "Sign the CSR at CSR_PATH with CONFIG"
    def sign_csr(config_path,csr_path)
      config = Config.from_yaml(File.read(config_path))
      config.command_specific = {"serial_number" => 0, "outfile" => "/tmp/temp.crt"}

      editor = Editor.new()
      on_change = lambda { |new_content|
        Log.debug new_content
        Config.from_yaml(new_content)
      }
      new_config = editor.edit!(config.to_yaml,on_change)
      config = new_config unless new_config.nil? ## User didn't do anything

      x509_cert = OpenSSL::X509::Certificate.new File.read(config.signing_cert)
      cert = CertificateAuthority::Certificate.from_openssl(x509_cert)
      key_material = CertificateAuthority::KeyMaterial.from_x509_key_pair(File.read(config.signing_key))
      cert.key_material = key_material

      signing_request = CertificateAuthority::SigningRequest.from_x509_csr File.read(csr_path)
      new_cert = signing_request.to_cert
      new_cert.serial_number.number = config.command_specific["serial_number"]
      new_cert.parent = cert

      if !config.signing_profile.nil?
        Log.info "Signing cert with a signing profile"
        new_cert = new_cert.sign!(config.signing_profile)
      else
        Log.info "Signing cert without a signing profile"
        puts new_cert.sign!
      end

      Log.info "Writing signed certificate to #{config.command_specific["outfile"]}"
      File.open(config.command_specific["outfile"],"w") {|f| f.write(new_cert.to_pem)}
    end
  end

  class Editor
    def initialize()
      @editor = get_env_editor()
    end

    def edit!(content,changed_callback)
      start_state = content
      temp = build_temp_file(content)
      shell_out_to_editor(temp.path)
      ## Open an entirely new file to make sure we get the change
      ## I think this is a problem in 1.9.3p124+?
      end_state = File.read(temp.path)
      result = nil
      if start_state != end_state
        result = changed_callback.call(end_state)
      else
        puts "No change"
      end
      temp.unlink
      result
    end

    private
    def shell_out_to_editor(filename)
      system("#{@editor} #{filename}")
      ret_val = $?
      raise "Editor didn't exit w/ 0 (#{ret_val}). Bailing." if ret_val != 0
    end

    def build_temp_file(content)
      temp = Tempfile.new("certificate_authority_cli")
      temp.write(content)
      temp.close
      temp
    end

    def get_env_editor
      editor = ENV['EDITOR']
      if editor.nil?
        puts "No editor was specified so you get vim"
        editor = "vim"
      end
      editor
    end

  end
end

CertificateAuthorityCli::Cli.start
