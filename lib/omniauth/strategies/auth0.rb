require 'base64'
require 'uri'
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    # Auth0 OmniAuth strategy
    class Auth0 < OmniAuth::Strategies::OAuth2
      option :name, 'auth0'

      args [
        :client_id,
        :client_secret,
        :domain
      ]

      def client
        options.client_options.site = domain_url
        options.client_options.authorize_url = '/authorize'
        options.client_options.token_url = '/oauth/token'
        options.client_options.userinfo_url = '/userinfo'
        super
      end

      uid { raw_info['sub'] }

      extra do
        {}
      end

      info do
        {}
      end

      private

      def domain_url
        domain_url = URI(options.domain)
        domain_url = URI("https://#{domain_url}") if domain_url.scheme.nil?
        domain_url.to_s
      end
    end
  end
end
