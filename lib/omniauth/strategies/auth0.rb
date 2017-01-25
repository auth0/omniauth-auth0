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

      credentials do
        hash = { 'token' => access_token.token }
        hash['expires'] = true
        if access_token.params
          hash['id_token'] = access_token.params['id_token']
          hash['token_type'] = access_token.params['token_type']
          hash['refresh_token'] = access_token.refresh_token
        end
        hash
      end

      extra do
        {
          raw_info: raw_info
        }
      end

      info do
        {
          name: raw_info['name'] || raw_info['sub'],
          nickname: raw_info['nickname'],
          email: raw_info['email'],
          image: raw_info['picture']
        }
      end

      def authorize_params
        params = super
        params['auth0Client'] = client_info
        params
      end

      def request_phase
        if no_client_id?
          fail!(:missing_client_id)
        elsif no_client_secret?
          fail!(:missing_client_secret)
        elsif no_domain?
          fail!(:missing_domain)
        else
          super
        end
      end

      private

      def raw_info
        userinfo_url = options.client_options.userinfo_url
        @raw_info ||= access_token.get(userinfo_url).parsed
      end

      def no_client_id?
        ['', nil].include?(options.client_id)
      end

      def no_client_secret?
        ['', nil].include?(options.client_secret)
      end

      def no_domain?
        ['', nil].include?(options.domain)
      end

      def domain_url
        domain_url = URI(options.domain)
        domain_url = URI("https://#{domain_url}") if domain_url.scheme.nil?
        domain_url.to_s
      end

      def client_info
        client_info = JSON.dump(
          name: 'omniauth-auth0',
          version: OmniAuth::Auth0::VERSION
        )
        Base64.urlsafe_encode64(client_info)
      end
    end
  end
end
