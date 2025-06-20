# frozen_string_literal: true

require 'spec_helper'
require 'jwt'
require 'multi_json'

OmniAuth.config.allowed_request_methods = [:get, :post]

RSpec.shared_examples 'site has valid domain url' do |url|
  it { expect(subject.site).to eq(url) }
end

describe OmniAuth::Strategies::Auth0 do
  let(:client_id) { 'CLIENT_ID' }
  let(:client_secret) { 'CLIENT_SECRET' }
  let(:domain_url) { 'https://samples.auth0.com' }
  let(:client_assertion_signing_algorithm) { 'RS256' }
  let(:client_assertion_signing_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:application) do
    lambda do
      [200, {}, ['Hello.']]
    end
  end
  let(:auth0) do
    OmniAuth::Strategies::Auth0.new(
      application,
      client_id,
      client_secret,
      domain_url
    )
  end
  let(:auth0_client_assertion_signing_key) do
    OmniAuth::Strategies::Auth0.new(
      application,
      client_id,
      nil,
      domain_url,
      { client_assertion_signing_key:, client_assertion_signing_algorithm: }
    )
  end
  describe 'client_options' do
    context 'when using client_secret authentication' do
      let(:subject) { OmniAuth::Strategies::Auth0.new(
        application,
        client_id,
        client_secret,
        domain_url
      ).client }

      context 'domain with https' do
        let(:domain_url) { 'https://samples.auth0.com' }
        it_behaves_like 'site has valid domain url', 'https://samples.auth0.com'
      end

      context 'domain with http' do
        let(:domain_url) { 'http://mydomain.com' }
        it_behaves_like 'site has valid domain url', 'http://mydomain.com'
      end

      context 'domain with host only' do
        let(:domain_url) { 'samples.auth0.com' }
        it_behaves_like 'site has valid domain url', 'https://samples.auth0.com'
      end

      it 'should have correct authorize path' do
        expect(subject.options[:authorize_url]).to eq('/authorize')
      end

      it 'should have the correct userinfo path' do
        expect(subject.options[:userinfo_url]).to eq('/userinfo')
      end

      it 'should have the correct token path' do
        expect(subject.options[:token_url]).to eq('/oauth/token')
      end
    end

    context 'when using client assertion signing key authentication' do
      let(:subject) do
        OmniAuth::Strategies::Auth0.new(
          application,
          client_id,
          nil,
          domain_url,
          { client_assertion_signing_key:, client_assertion_signing_algorithm: }
        ).client
      end

      context 'domain with https' do
        let(:domain_url) { 'https://samples.auth0.com' }
        it_behaves_like 'site has valid domain url', 'https://samples.auth0.com'
      end

      context 'domain with http' do
        let(:domain_url) { 'http://mydomain.com' }
        it_behaves_like 'site has valid domain url', 'http://mydomain.com'
      end

      context 'domain with host only' do
        let(:domain_url) { 'samples.auth0.com' }
        it_behaves_like 'site has valid domain url', 'https://samples.auth0.com'
      end

      it 'should have correct authorize path' do
        expect(subject.options[:authorize_url]).to eq('/authorize')
      end

      it 'should have the correct userinfo path' do
        expect(subject.options[:userinfo_url]).to eq('/userinfo')
      end

      it 'should have the correct token path' do
        expect(subject.options[:token_url]).to eq('/oauth/token')
      end

      it 'should have the correct auth_scheme' do
        expect(subject.options[:auth_scheme]).to eq(:private_key_jwt)
      end
    end
  end

  describe 'options' do
    context 'when using client_secret authentication' do
      let(:subject) { auth0.options }

      it 'should have the correct client_id' do
        expect(subject[:client_id]).to eq(client_id)
      end

      it 'should have the correct client secret' do
        expect(subject[:client_secret]).to eq(client_secret)
      end
      it 'should have correct domain' do
        expect(subject[:domain]).to eq(domain_url)
      end
    end

    context 'when using client assertion signing key authentication' do
      let(:subject) { auth0_client_assertion_signing_key.options }

      it 'should have the correct client_id' do
        expect(subject[:client_id]).to eq(client_id)
      end

      it 'should have the correct client secret' do
        expect(subject[:client_secret]).to eq(nil)
      end
      it 'should have correct domain' do
        expect(subject[:domain]).to eq(domain_url)
      end

      it 'should have the correct client_assertion_signing_key' do
        expect(subject[:client_assertion_signing_key]).to eq(client_assertion_signing_key)
      end
    end
  end

  describe 'oauth' do
    context 'when using client_secret authentication' do
      it 'redirects to hosted login page' do
        get 'auth/auth0'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('connection_scope')
        expect(redirect_url).not_to have_query('prompt')
        expect(redirect_url).not_to have_query('screen_hint')
        expect(redirect_url).not_to have_query('login_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it 'redirects to hosted login page' do
        get 'auth/auth0?connection=abcd'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('connection', 'abcd')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection_scope')
        expect(redirect_url).not_to have_query('prompt')
        expect(redirect_url).not_to have_query('screen_hint')
        expect(redirect_url).not_to have_query('login_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it 'redirects to the hosted login page with connection_scope' do
        get 'auth/auth0?connection_scope=identity_provider_scope'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url)
          .to have_query('connection_scope', 'identity_provider_scope')
      end

      it 'redirects to hosted login page with prompt=login' do
        get 'auth/auth0?prompt=login'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('prompt', 'login')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('login_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it 'redirects to hosted login page with screen_hint=signup' do
        get 'auth/auth0?screen_hint=signup'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('screen_hint', 'signup')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('login_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it 'redirects to hosted login page with organization=TestOrg and invitation=TestInvite' do
        get 'auth/auth0?organization=TestOrg&invitation=TestInvite'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('organization', 'TestOrg')
        expect(redirect_url).to have_query('invitation', 'TestInvite')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('connection_scope')
        expect(redirect_url).not_to have_query('prompt')
        expect(redirect_url).not_to have_query('screen_hint')
        expect(redirect_url).not_to have_query('login_hint')
      end

      it 'redirects to hosted login page with login_hint=example@mail.com' do
        get 'auth/auth0?login_hint=example@mail.com'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('login_hint', 'example@mail.com')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('connection_scope')
        expect(redirect_url).not_to have_query('prompt')
        expect(redirect_url).not_to have_query('screen_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it "stores session['authorize_params'] as a plain Ruby Hash" do
        get '/auth/auth0'

        expect(session['authorize_params'].class).to eq(::Hash)
      end
    end

    context 'when using client assertion signing key authentication' do
      before do
        @app = make_application(client_secret: nil, client_assertion_signing_key:, client_assertion_signing_algorithm:)
      end

      it 'redirects to hosted login page' do
        get 'auth/auth0'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('connection_scope')
        expect(redirect_url).not_to have_query('prompt')
        expect(redirect_url).not_to have_query('screen_hint')
        expect(redirect_url).not_to have_query('login_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it 'redirects to hosted login page' do
        get 'auth/auth0?connection=abcd'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('connection', 'abcd')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection_scope')
        expect(redirect_url).not_to have_query('prompt')
        expect(redirect_url).not_to have_query('screen_hint')
        expect(redirect_url).not_to have_query('login_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it 'redirects to the hosted login page with connection_scope' do
        get 'auth/auth0?connection_scope=identity_provider_scope'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url)
          .to have_query('connection_scope', 'identity_provider_scope')
      end

      it 'redirects to hosted login page with prompt=login' do
        get 'auth/auth0?prompt=login'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('prompt', 'login')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('login_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it 'redirects to hosted login page with screen_hint=signup' do
        get 'auth/auth0?screen_hint=signup'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('screen_hint', 'signup')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('login_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it 'redirects to hosted login page with organization=TestOrg and invitation=TestInvite' do
        get 'auth/auth0?organization=TestOrg&invitation=TestInvite'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('organization', 'TestOrg')
        expect(redirect_url).to have_query('invitation', 'TestInvite')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('connection_scope')
        expect(redirect_url).not_to have_query('prompt')
        expect(redirect_url).not_to have_query('screen_hint')
        expect(redirect_url).not_to have_query('login_hint')
      end

      it 'redirects to hosted login page with login_hint=example@mail.com' do
        get 'auth/auth0?login_hint=example@mail.com'
        expect(last_response.status).to eq(302)
        redirect_url = last_response.headers['Location']
        expect(redirect_url).to start_with('https://samples.auth0.com/authorize')
        expect(redirect_url).to have_query('response_type', 'code')
        expect(redirect_url).to have_query('state')
        expect(redirect_url).to have_query('client_id')
        expect(redirect_url).to have_query('redirect_uri')
        expect(redirect_url).to have_query('login_hint', 'example@mail.com')
        expect(redirect_url).not_to have_query('auth0Client')
        expect(redirect_url).not_to have_query('connection')
        expect(redirect_url).not_to have_query('connection_scope')
        expect(redirect_url).not_to have_query('prompt')
        expect(redirect_url).not_to have_query('screen_hint')
        expect(redirect_url).not_to have_query('organization')
        expect(redirect_url).not_to have_query('invitation')
      end

      it "stores session['authorize_params'] as a plain Ruby Hash" do
        get '/auth/auth0'

        expect(session['authorize_params'].class).to eq(::Hash)
      end
    end

    def session
      session_cookie = last_response.cookies['rack.session'].first
      session_data, _, _ = session_cookie.rpartition('--')
      decoded_session_data = Base64.decode64(session_data)
      Marshal.load(decoded_session_data)
    end

    describe 'callback' do
      let(:access_token) { 'access token' }
      let(:expires_in) { 2000 }
      let(:token_type) { 'bearer' }
      let(:refresh_token) { 'refresh token' }
      let(:telemetry_value) { Class.new.extend(OmniAuth::Auth0::Telemetry).telemetry_encoded }

      let(:user_id) { 'user identifier' }
      let(:state) { SecureRandom.hex(8) }
      let(:name) { 'John' }
      let(:nickname) { 'J' }
      let(:picture) { 'some picture url' }
      let(:email) { 'mail@mail.com' }
      let(:email_verified) { true }

      let(:oauth_response) do
        {
          access_token: access_token,
          expires_in: expires_in,
          token_type: token_type
        }
      end

      let(:oidc_response) do
        {
          id_token: id_token,
          access_token: access_token,
          expires_in: expires_in,
          token_type: token_type
        }
      end

      let(:basic_user_info) { { "sub" => user_id, "name" => name } }

      def stub_userinfo(body)
        stub_request(:get, 'https://samples.auth0.com/userinfo')
          .to_return(
            headers: { 'Content-Type' => 'application/json' },
            body: MultiJson.encode(body)
          )
      end

      def trigger_callback
        get '/auth/auth0/callback', { 'state' => state },
            'rack.session' => { 'omniauth.state' => state }
      end

      before(:each) do
        WebMock.reset!
      end

      let(:subject) do
        MultiJson.decode(last_response.body)
      end

      context 'when using client_secret authentication' do
        let(:id_token) do
          payload = {}
          payload['sub'] = user_id
          payload['iss'] = "#{domain_url}/"
          payload['aud'] = client_id
          payload['name'] = name
          payload['nickname'] = nickname
          payload['picture'] = picture
          payload['email'] = email
          payload['email_verified'] = email_verified

          JWT.encode payload, client_secret, 'HS256'
        end

        def stub_auth(body)
          stub_request(:post, 'https://samples.auth0.com/oauth/token')
            .with(headers: { 'Auth0-Client' => telemetry_value })
            .to_return(
              headers: { 'Content-Type' => 'application/json' },
              body: MultiJson.encode(body)
            )
        end

        context 'basic oauth' do
          before do
            stub_auth(oauth_response)
            stub_userinfo(basic_user_info)
            trigger_callback
          end

          it 'to succeed' do
            expect(last_response.status).to eq(200)
          end

          it 'has credentials' do
            expect(subject['credentials']['token']).to eq(access_token)
            expect(subject['credentials']['expires']).to be true
            expect(subject['credentials']['expires_at']).to_not be_nil
          end

          it 'has basic values' do
            expect(subject['provider']).to eq('auth0')
            expect(subject['uid']).to eq(user_id)
            expect(subject['info']['name']).to eq(name)
          end

          it 'should use the user info endpoint' do
            expect(subject['extra']['raw_info']).to eq(basic_user_info)
          end
        end

        context 'basic oauth w/refresh token' do
          before do
            stub_auth(oauth_response.merge(refresh_token: refresh_token))
            stub_userinfo(basic_user_info)
            trigger_callback
          end

          it 'to succeed' do
            expect(last_response.status).to eq(200)
          end

          it 'has credentials' do
            expect(subject['credentials']['token']).to eq(access_token)
            expect(subject['credentials']['refresh_token']).to eq(refresh_token)
            expect(subject['credentials']['expires']).to be true
            expect(subject['credentials']['expires_at']).to_not be_nil
          end
        end

        context 'oidc' do
          before do
            stub_auth(oidc_response)
            trigger_callback
          end

          it 'to succeed' do
            expect(last_response.status).to eq(200)
          end

          it 'has credentials' do
            expect(subject['credentials']['token']).to eq(access_token)
            expect(subject['credentials']['expires']).to be true
            expect(subject['credentials']['expires_at']).to_not be_nil
            expect(subject['credentials']['id_token']).to eq(id_token)
          end

          it 'has basic values' do
            expect(subject['provider']).to eq('auth0')
            expect(subject['uid']).to eq(user_id)
          end

          it 'has info' do
            expect(subject['info']['name']).to eq(name)
            expect(subject['info']['nickname']).to eq(nickname)
            expect(subject['info']['image']).to eq(picture)
            expect(subject['info']['email']).to eq(email)
          end

          it 'has extra' do
            expect(subject['extra']['raw_info']['email_verified']).to be true
          end
        end
      end

      context 'when using client assertion signing key authentication' do
        let(:jwt_token) { JWT.encode({ sub: client_id }, client_assertion_signing_key, 'RS256') }
        let(:valid_jwks_kid) { 'NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg' }

        let(:rsa_private_key) do
          OpenSSL::PKey::RSA.generate 2048
        end

        let(:valid_jwks) do
          {
            keys: [
              {
                kid: valid_jwks_kid,
                x5c: [Base64.encode64(make_cert(rsa_private_key).to_der)]
              }
            ]
          }.to_json
        end

        let(:id_token) do
          payload = {}
          payload['sub'] = user_id
          payload['iss'] = "#{domain_url}/"
          payload['aud'] = client_id
          payload['name'] = name
          payload['nickname'] = nickname
          payload['picture'] = picture
          payload['email'] = email
          payload['email_verified'] = email_verified

          JWT.encode payload, rsa_private_key, 'RS256', kid: valid_jwks_kid
        end

        def make_cert(private_key)
          cert = OpenSSL::X509::Certificate.new
          cert.issuer = OpenSSL::X509::Name.parse('/C=BE/O=Auth0/OU=Auth0/CN=Auth0')
          cert.subject = cert.issuer
          cert.not_before = Time.now
          cert.not_after = Time.now + 365 * 24 * 60 * 60
          cert.public_key = private_key.public_key
          cert.serial = 0x0
          cert.version = 2

          ef = OpenSSL::X509::ExtensionFactory.new
          ef.subject_certificate = cert
          ef.issuer_certificate = cert
          cert.extensions = [
            ef.create_extension('basicConstraints', 'CA:TRUE', true),
            ef.create_extension('subjectKeyIdentifier', 'hash')
          ]
          cert.add_extension ef.create_extension(
            'authorityKeyIdentifier',
            'keyid:always,issuer:always'
          )

          cert.sign private_key, OpenSSL::Digest.new('SHA1')
        end

        def stub_auth(body)
          stub_request(:post, "#{domain_url}/oauth/token")
            .with(headers: { 'Auth0-Client' => telemetry_value },
                  body: hash_including({ 'grant_type' => described_class::AUTHORIZATION_CODE_GRANT_TYPE,
                                         'code' => nil,
                                         'client_assertion_type' => described_class::CLIENT_ASSERTION_TYPE,
                                         'client_assertion' => jwt_token,
                                         'audience' => domain_url }))
            .to_return(
              headers: { 'Content-Type' => 'application/json' },
              body: MultiJson.encode(body)
            )
        end

        def stub_expected_jwks
          stub_request(:get, 'https://samples.auth0.com/.well-known/jwks.json')
            .to_return(
              headers: { 'Content-Type' => 'application/json' },
              body: valid_jwks,
              status: 200
            )
        end

        def stub_jwt_token(algorithm: client_assertion_signing_algorithm)
          allow(OmniAuth::Auth0::JWTToken).to receive(:new)
            .with(client_id:,
                  domain_url:,
                  client_assertion_signing_key:,
                  client_assertion_signing_algorithm: algorithm)
            .and_return(instance_double(OmniAuth::Auth0::JWTToken, jwt_token:))
        end

        context 'basic oauth' do
          before do
            @app = make_application(client_secret: nil, client_assertion_signing_key:)
            stub_jwt_token(algorithm: nil)
            stub_auth(oauth_response)
            stub_userinfo(basic_user_info)
            trigger_callback
          end

          it 'to succeed' do
            expect(last_response.status).to eq(200)
          end

          it 'has credentials' do
            expect(subject['credentials']['token']).to eq(access_token)
            expect(subject['credentials']['expires']).to be true
            expect(subject['credentials']['expires_at']).to_not be_nil
          end

          it 'has basic values' do
            expect(subject['provider']).to eq('auth0')
            expect(subject['uid']).to eq(user_id)
            expect(subject['info']['name']).to eq(name)
          end

          it 'should use the user info endpoint' do
            expect(subject['extra']['raw_info']).to eq(basic_user_info)
          end
        end

        context 'basic oauth w/refresh token' do
          before do
            @app = make_application(client_secret: nil,
                                    client_assertion_signing_key:,
                                    client_assertion_signing_algorithm:)
            stub_jwt_token
            stub_auth(oauth_response.merge(refresh_token:))
            stub_userinfo(basic_user_info)
            trigger_callback
          end

          it 'to succeed' do
            expect(last_response.status).to eq(200)
          end

          it 'has credentials' do
            expect(subject['credentials']['token']).to eq(access_token)
            expect(subject['credentials']['refresh_token']).to eq(refresh_token)
            expect(subject['credentials']['expires']).to be true
            expect(subject['credentials']['expires_at']).to_not be_nil
          end
        end

        context 'oidc' do
          before do
            @app = make_application(client_secret: nil,
                                    client_assertion_signing_key:,
                                    client_assertion_signing_algorithm:)
            stub_jwt_token
            stub_auth(oidc_response)
            stub_expected_jwks
            trigger_callback
          end

          it 'to succeed' do
            expect(last_response.status).to eq(200)
          end

          it 'has credentials' do
            expect(subject['credentials']['token']).to eq(access_token)
            expect(subject['credentials']['expires']).to be true
            expect(subject['credentials']['expires_at']).to_not be_nil
            expect(subject['credentials']['id_token']).to eq(id_token)
          end

          it 'has basic values' do
            expect(subject['provider']).to eq('auth0')
            expect(subject['uid']).to eq(user_id)
          end

          it 'has info' do
            expect(subject['info']['name']).to eq(name)
            expect(subject['info']['nickname']).to eq(nickname)
            expect(subject['info']['image']).to eq(picture)
            expect(subject['info']['email']).to eq(email)
          end

          it 'has extra' do
            expect(subject['extra']['raw_info']['email_verified']).to be true
          end
        end
      end
    end
  end

  describe 'error_handling' do
    it 'fails when missing client_id and client_assertion_signing_key' do
      @app = make_application(client_id: nil)
      get 'auth/auth0'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to fail_auth_with('missing_client_id')
    end

    it 'fails when missing client_secret and client_assertion_signing_key' do
      @app = make_application(client_secret: nil)
      get 'auth/auth0'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to fail_auth_with('missing_client_secret')
    end

    it 'fails when missing domain' do
      @app = make_application(domain: nil)
      get 'auth/auth0'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to fail_auth_with('missing_domain')
    end

    it 'fails when missing client_assertion_signing_key' do
      @app = make_application(client_secret: nil, client_assertion_signing_key: nil)
      get 'auth/auth0'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to fail_auth_with('missing_client_assertion_signing_key')
    end
  end
end

RSpec::Matchers.define :fail_auth_with do |message|
  match do |actual|
    uri = URI(actual)
    query = CGI.parse(uri.query)
    (uri.path == '/auth/failure') &&
      (query['message'] == [message]) &&
      (query['strategy'] == ['auth0'])
  end
end

RSpec::Matchers.define :have_query do |key, value|
  match do |actual|
    uri = redirect_uri(actual)
    query = query(uri)
    if value.nil?
      query.key?(key)
    else
      query[key] == [value]
    end
  end

  def redirect_uri(string)
    URI(string)
  end

  def query(uri)
    CGI.parse(uri.query)
  end
end
