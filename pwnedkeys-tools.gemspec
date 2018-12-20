begin
  require 'git-version-bump'
rescue LoadError
  nil
end

Gem::Specification.new do |s|
  s.name = "pwnedkeys-tools"

  s.version = GVB.version rescue "0.0.0.1.NOGVB"
  s.date    = GVB.date    rescue Time.now.strftime("%Y-%m-%d")

  s.platform = Gem::Platform::RUBY

  s.summary  = "A set of command-line tools useful for working with the pwnedkeys.com service"
  s.description = <<~EOF
    The scripts in this package are designed to be used in conjunction with the
    pwnedkeys.com compromised keys database.  They include:
    
    * `pwnedkeys-prove-pwned`, which generates a signed attestation of
      compromise suitable for being served by the pwnedkeys.com V1 API.

    * `pwnedkeys-query`, which takes a public or private key, CSR, or X.509
      certificate and looks it up in the pwnedkeys.com database.
  EOF

  s.authors  = ["Matt Palmer"]
  s.email    = ["matt@hezmatt.org"]
  s.homepage = "https://github.com/pwnedkeys/pwnedkeys-tools"

  s.files = `git ls-files -z`.split("\0").reject { |f| f =~ /^(\.|G|spec|Rakefile)/ }
  s.executables = ["pwnedkeys-prove-pwned", "pwnedkeys-query"]

  s.required_ruby_version = ">= 2.5.0"

  s.add_runtime_dependency "pwnedkeys-api-client"

  s.add_development_dependency 'bundler'
  s.add_development_dependency 'github-release'
  s.add_development_dependency 'git-version-bump'
  s.add_development_dependency 'guard-rspec'
  s.add_development_dependency 'rack-test'
  s.add_development_dependency 'rake', "~> 12.0"
  s.add_development_dependency 'redcarpet'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'yard'
end
