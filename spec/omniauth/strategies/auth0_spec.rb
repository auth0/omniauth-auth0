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

  describe 'client_options' do
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

  describe 'options' do
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

  describe 'oauth' do
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

    def session
      session_cookie = last_response.cookies['rack.session'].first
      session_data, _, _ = session_cookie.rpartition('--')
      decoded_session_data = Base64.decode64(session_data)
      Marshal.load(decoded_session_data)
    end

    it "stores session['authorize_params'] as a plain Ruby Hash" do
      get '/auth/auth0'

      expect(session['authorize_params'].class).to eq(::Hash)
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

      def stub_auth(body)
        stub_request(:post, 'https://samples.auth0.com/oauth/token')
          .with(headers: { 'Auth0-Client' => telemetry_value })
          .to_return(
            headers: { 'Content-Type' => 'application/json' },
            body: MultiJson.encode(body)
          )
      end

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

        it 'has basic values'  do
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
  end

  describe 'error_handling' do
    it 'fails when missing client_id' do
      @app = make_application(client_id: nil)
      get 'auth/auth0'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to fail_auth_with('missing_client_id')
    end

    it 'fails when missing client_secret' do
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
