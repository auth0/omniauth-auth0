require 'base64'
require 'uri'
require 'json'
require 'omniauth'

module OmniAuth
  module Auth0
    # JWT Validator class
    class JWTValidator
      attr_accessor :issuer, :domain

      # Initializer
      # @param options object
      #   options.domain - Application domain.
      #   options.issuer - Application issuer (optional).
      #   options.client_id - Application Client ID.
      #   options.client_secret - Application Client Secret.
      def initialize(options)
        @domain = uri_string(options.domain)
        @key_host_uri = uri_string(options.key_host)

        # Use custom issuer if provided, otherwise use domain
        @issuer = @domain
        @issuer = uri_string(options.issuer) if options.respond_to?(:issuer)

        @client_id = options.client_id
        @client_secret = options.client_secret
      end

      # Decode a JWT.
      # @param jwt string - JWT to decode.
      # @return hash - The decoded token, if there were no exceptions.
      # @see https://github.com/jwt/ruby-jwt
      def decode(jwt)
        head = token_head(jwt)

        # Make sure the algorithm is supported and get the decode key.
        decode_key = @client_secret
        if head[:alg] == 'RS256'
          decode_key = rs256_decode_key(head[:kid])
        elsif head[:alg] != 'HS256'
          raise JWT::VerificationError, :id_token_alg_unsupported
        end

        # Docs: https://github.com/jwt/ruby-jwt#algorithms-and-usage
        JWT.decode(jwt, decode_key, true, decode_opts(head[:alg]))
      end

      # Get the decoded head segment from a JWT.
      # @return hash - The parsed head of the JWT passed, empty hash if not.
      def token_head(jwt)
        jwt_parts = jwt.split('.')
        return {} if blank?(jwt_parts) || blank?(jwt_parts[0])

        json_parse(Base64.decode64(jwt_parts[0]))
      end

      # Get the JWKS from the issuer and return a public key.
      # @param x5c string - X.509 certificate chain from a JWKS.
      # @return key - The X.509 certificate public key.
      def jwks_public_cert(x5c)
        x5c = Base64.decode64(x5c)

        # https://docs.ruby-lang.org/en/2.4.0/OpenSSL/X509/Certificate.html
        OpenSSL::X509::Certificate.new(x5c).public_key
      end

      # Return a specific key from a JWKS object.
      # @param key string - Key to find in the JWKS.
      # @param kid string - Key ID to identify the right JWK.
      # @return nil|string
      def jwks_key(key, kid)
        return nil if blank?(jwks[:keys])

        matching_jwk = jwks[:keys].find { |jwk| jwk[:kid] == kid }
        matching_jwk[key] if matching_jwk
      end

      private

      # Get the JWT decode options
      # Docs: https://github.com/jwt/ruby-jwt#add-custom-header-fields
      # @return hash
      def decode_opts(alg)
        {
          algorithm: alg,
          leeway: 30,
          verify_expiration: true,
          verify_iss: true,
          iss: @issuer,
          verify_aud: true,
          aud: @client_id,
          verify_not_before: true
        }
      end

      def rs256_decode_key(kid)
        jwks_x5c = jwks_key(:x5c, kid)
        raise JWT::VerificationError, :jwks_missing_x5c if jwks_x5c.nil?

        jwks_public_cert(jwks_x5c.first)
      end

      # Get a JWKS from the domain
      # @return void
      def jwks
        jwks_uri = URI(@key_host_uri + '.well-known/jwks.json')
        @jwks ||= json_parse(Net::HTTP.get(jwks_uri))
      end

      # Rails Active Support blank method.
      # @param obj object - Object to check for blankness.
      # @return boolean
      def blank?(obj)
        obj.respond_to?(:empty?) ? obj.empty? : !obj
      end

      # Parse JSON with symbolized names.
      # @param json string - JSON to parse.
      # @return hash
      def json_parse(json)
        JSON.parse(json, symbolize_names: true)
      end

      # Parse a URI into the desired string format
      # @param uri - the URI to parse
      # @return string
      def uri_string(uri)
        temp_domain = URI(uri)
        temp_domain = URI("https://#{uri}") unless temp_domain.scheme
        "#{temp_domain}/"
      end
    end
  end
end
