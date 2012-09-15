# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'certificate_authority_cli/version'

Gem::Specification.new do |gem|
  gem.name          = "certificate_authority_cli"
  gem.version       = CertificateAuthorityCli::VERSION
  gem.authors       = ["Chris Chandler"]
  gem.email         = ["cchandler@squareup.com"]
  gem.description   = %q{TODO: Write a gem description}
  gem.summary       = %q{TODO: Write a gem summary}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

end
