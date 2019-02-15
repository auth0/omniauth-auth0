require 'json'

module OmniAuth
  module Auth0
    # Module to provide necessary telemetry for API requests.
    module Telemetry
      def telemetry
        @telemetry = {
          name: 'omniauth-auth0',
          version: OmniAuth::Auth0::VERSION,
          env: {
            ruby: RUBY_VERSION
          }
        }
        add_rails_version
      end

      def telemetry_encoded
        Base64.urlsafe_encode64(JSON.dump(@telemetry))
      end

      private

      def add_rails_version
        return unless Gem.loaded_specs['rails'].respond_to? :version
        @telemetry[:env][:rails] = Gem.loaded_specs['rails'].version.to_s
      end
    end
  end
end
