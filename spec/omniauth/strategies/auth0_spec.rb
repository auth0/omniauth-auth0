require 'spec_helper'

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
    let(:subject) { auth0.client }

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
      query[key].length == 1
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
