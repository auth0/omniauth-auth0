require 'base64'
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    # Auth0 OmniAuth strategy
    class Auth0 < OmniAuth::Strategies::OAuth2
      option :name, 'auth0'

      option :client_options, {
        authorize_url: '/authorize',
        token_url: '/oauth/token',
        userinfo_url: '/userinfo'
      }

      args [
        :client_id,
        :client_secret
      ]

      uid { raw_info['sub'] }

      extra do
        {}
      end

      info do
        {}
      end
    end
  end
end
