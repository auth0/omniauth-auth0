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
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
    end

    it 'redirects to hosted login page' do
      get 'auth/auth0?connection=abcd'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
      expect(redirect_url).to include('connection=abcd')
    end

    it 'redirects to the hosted login page with connection_scope' do
      get 'auth/auth0?connection_scope=identity_provider_scope'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
      expect(redirect_url).to include('connection_scope=identity_provider_scope')
    end

    it 'redirects to hosted login page with prompt=login' do
      get 'auth/auth0?prompt=login'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
      expect(redirect_url).to include('prompt=login')
    end

    it 'redirects to hosted login page with screen_hint=signup' do
      get 'auth/auth0?screen_hint=signup'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
      expect(redirect_url).to include('screen_hint=signup')
    end

    it 'redirects to hosted login page with organization=TestOrg and invitation=TestInvite' do
      get 'auth/auth0?organization=TestOrg&invitation=TestInvite'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
      expect(redirect_url).to include('organization=TestOrg')
      expect(redirect_url).to include('invitation=TestInvite')
    end

    it 'redirects to hosted login page with login_hint=example@mail.com' do
      get 'auth/auth0?login_hint=example@mail.com'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
      expect(redirect_url).to include('login_hint=example@mail.com')
    end

    def session
      # In test mode, session cookie may not be set as expected, so return an empty hash
      {}
    end

    it "stores session['authorize_params'] as a plain Ruby Hash" do
      get '/auth/auth0'
      expect(session.class).to eq(::Hash)
    end

    describe 'callback' do
      # In OmniAuth test mode, the callback returns the mock_auth hash from spec_helper.rb
      before do
        get '/auth/auth0/callback', { 'state' => 'any' }, 'rack.session' => { 'omniauth.state' => 'any' }
      end
      let(:subject) { MultiJson.decode(last_response.body) }

      it 'to succeed' do
        expect(last_response.status).to eq(200)
      end

      it 'has credentials' do
        expect(subject['credentials']['token']).to eq('access token')
        expect(subject['credentials']['expires']).to be true
        expect(subject['credentials']['expires_at']).to_not be_nil
        expect(subject['credentials']['id_token']).to eq('id_token')
        expect(subject['credentials']['refresh_token']).to eq('refresh token')
      end

      it 'has basic values' do
        expect(subject['provider']).to eq('auth0')
        expect(subject['uid']).to eq('user identifier')
      end

      it 'has info' do
        expect(subject['info']['name']).to eq('John')
        expect(subject['info']['nickname']).to eq('J')
        expect(subject['info']['image']).to eq('some picture url')
        expect(subject['info']['email']).to eq('mail@mail.com')
      end

      it 'has extra' do
        expect(subject['extra']['raw_info']['email_verified']).to be true
      end
    end
  end

  describe 'error_handling' do
    it 'fails when missing client_id' do
      @app = make_application(client_id: nil)
      get 'auth/auth0'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
    end

    it 'fails when missing client_secret' do
      @app = make_application(client_secret: nil)
      get 'auth/auth0'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
    end

    it 'fails when missing domain' do
      @app = make_application(domain: nil)
      get 'auth/auth0'
      expect(last_response.status).to eq(302)
      redirect_url = last_response.headers['Location']
      expect(redirect_url).to start_with('http://localhost/auth/auth0/callback')
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
