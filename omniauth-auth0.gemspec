# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "omniauth-auth0/version"

Gem::Specification.new do |s|
  s.name        = "omniauth-auth0"
  s.version     = OmniAuth::Auth0::VERSION
  s.authors     = ["Auth0", "Ezequiel Morito", "Jose Romaniello"]
  s.email       = ["support@auth0.com"]
  s.homepage    = "https://github.com/auth0/omniauth-auth0"
  s.summary     = %q{Omniauth OAuth2 strategy for the Auth0 platform.}
  s.description = %q{Auth0 is an authentication broker that supports social identity providers as well as enterprise identity providers such as Active Directory, LDAP, Google Apps, Salesforce.

OmniAuth is a library that standardizes multi-provider authentication for web applications. It was created to be powerful, flexible, and do as little as possible.

omniauth-auth0 is the omniauth strategy for Auth0.
}

  s.rubyforge_project = "omniauth-auth0"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_runtime_dependency 'omniauth-oauth2', '~> 1.1'

  s.add_development_dependency 'rspec',     '~> 2.7'
  s.add_development_dependency 'rack-test', '~> 0.6', '>= 0.6.3'
  s.add_development_dependency 'simplecov', '~> 0.9', '>= 0.9.1'
  s.add_development_dependency 'webmock', '~> 1.20', '>= 1.20.4'
  s.add_development_dependency 'rake', '~> 10.3', '>= 10.3.2'
  s.add_development_dependency 'gem-release', '~> 0.7'
  
  s.license = 'MIT'
end
