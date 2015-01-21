# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "auth0/version"

Gem::Specification.new do |s|
  s.name        = "omniauth-auth0"
  s.version     = Auth0::VERSION
  s.authors     = ["Auth0", "Ezequiel Morito", "Jose Romaniello"]
  s.email       = ["support@auth0.com"]
  s.homepage    = "https://github.com/auth0/omniauth-auth0"
  s.summary     = %q{Omniauth OAuth2 strategy for the Auth0 platform.}
  s.description = %q{Omniauth OAuth2 strategy for the Auth0 platform.}

  s.rubyforge_project = "omniauth-auth0"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_runtime_dependency 'omniauth-oauth2', '~> 1.1'

  s.add_development_dependency 'rspec', '~> 2.7'
  s.add_development_dependency 'rack-test', '~> 0.6.3'
  s.add_development_dependency 'simplecov', '~> 0.9.1'
  s.add_development_dependency 'webmock', '~> 1.20.4'
  s.add_development_dependency 'rake', '~> 10.3.2'

  s.license = 'MIT'
end