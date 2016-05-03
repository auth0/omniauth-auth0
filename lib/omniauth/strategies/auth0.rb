require "base64"
require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class Auth0 < OmniAuth::Strategies::OAuth2
      PASSTHROUGHS = %w[
        connection
        redirect_uri
      ]

      option :name, "auth0"
      option :namespace, nil
      option :provider_ignores_state, true
      option :connection

      option :client_options, {
        authorize_url: "/authorize",
        token_url: "/oauth/token",
        userinfo_url: "/userinfo"
      }

      args [:client_id, :client_secret, :namespace, :provider_ignores_state, :connection]

      def initialize(app, *args, &block)
        super

        if options[:namespace]
          @options.provider_ignores_state = args[3] unless args[3].nil?
          @options.connection = args[4] unless args[4].nil?

          @options.client_options.site =
            "https://#{options[:namespace]}"
          @options.client_options.authorize_url =
            "https://#{options[:namespace]}/authorize?#{self.class.client_info_querystring}"
          @options.client_options.token_url =
            "https://#{options[:namespace]}/oauth/token?#{self.class.client_info_querystring}"
          @options.client_options.userinfo_url =
            "https://#{options[:namespace]}/userinfo"
        elsif !options[:setup]
          fail(ArgumentError.new("Received wrong number of arguments. #{args.inspect}"))
        end
      end

      def authorize_params
        super.tap do |param|
          PASSTHROUGHS.each do |p|
            param[p.to_sym] = request.params[p] if request.params[p]
          end
          if @options.connection
            param[:connection] = @options.connection
          end
        end
      end

      credentials do
        hash = {'token' => access_token.token}
        hash.merge!('expires' => true)
        if access_token.params
          hash.merge!('id_token' => access_token.params['id_token'])
          hash.merge!('token_type' => access_token.params['token_type'])
          hash.merge!('refresh_token' => access_token.refresh_token) if access_token.refresh_token
        end
        hash
      end

      uid { raw_info["user_id"] }

      extra do
        { :raw_info => raw_info }
      end

      info do
        {
          :name => raw_info["name"],
          :email => raw_info["email"],
          :nickname => raw_info["nickname"],
          :first_name => raw_info["given_name"],
          :last_name => raw_info["family_name"],
          :location => raw_info["locale"],
          :image => raw_info["picture"]
        }
      end

      def raw_info
        @raw_info ||= access_token.get(options.client_options.userinfo_url).parsed
      end

      def self.client_info_querystring
        client_info = JSON.dump({name: 'omniauth-auth0', version: OmniAuth::Auth0::VERSION})
        "auth0Client=" + Base64.urlsafe_encode64(client_info)
      end
    end
  end
end
