require "spec_helper"

describe OmniAuth::Strategies::Auth0 do
  let(:app){ Rack::Builder.new do |b|
    b.use Rack::Session::Cookie, {:secret => "abc123"}
    b.run lambda{|env| [200, {}, ['Not Found']]}
  end.to_app }

  before :each do
    OmniAuth.config.test_mode = true
    @request = double('Request')
    allow(@request).to receive(:params)
    allow(@request).to receive(:cookies)
    allow(@request).to receive(:env)

    @session = double('Session')
    allow(@session).to receive(:delete).with('omniauth.state').and_return('state')
  end

  after do
    OmniAuth.config.test_mode = false
  end

  subject do
    OmniAuth::Strategies::Auth0.new(app,
        "client_id", "client_secret", "tenny.auth0.com:3000").tap do |strategy|
      allow(strategy).to receive(:request) { @request }
    end
  end

  context "initiation" do
    let(:base64_token) {
      Base64.urlsafe_encode64('{"name":"omniauth-auth0","version":"' + OmniAuth::Auth0::VERSION + '"}')
    }

    it "uses the correct site" do
      expect(subject.options.client_options.site).to eql "https://tenny.auth0.com:3000"
    end

    it "uses the correct authorize_url" do
      expect(subject.options.client_options.authorize_url).
        to eql "https://tenny.auth0.com:3000/authorize?auth0Client=#{base64_token}"

    end

    it "uses the correct token_url" do
      expect(subject.options.client_options.token_url).
        to eql "https://tenny.auth0.com:3000/oauth/token?auth0Client=#{base64_token}"
    end

    it "uses the correct userinfo url" do
      expect(subject.options.client_options.userinfo_url).
        to eql "https://tenny.auth0.com:3000/userinfo"
    end

    it "should raise an ArgumentError error if no namespace passed" do
      expect {
        OmniAuth::Strategies::Auth0.new(app, "client_id", "client_secret")
       }.to raise_error(ArgumentError)
    end
  end

  context "request phase" do
    before(:each){ get '/auth/auth0' }

    it "authenticate" do
      expect(last_response.status).to eq(200)
    end

    it "authorize params" do
      allow(subject).to receive(:request) { double('Request', {:params => {
        "connection" => "google-oauth2", "redirect_uri" => "redirect_uri" }, :env => {}}) }
      expect(subject.authorize_params).to include("connection")
      expect(subject.authorize_params).to include("state")
      expect(subject.authorize_params).to include("redirect_uri")
    end
  end

  describe "callback phase" do
    before :each do
      @raw_info = {
        "_id" => "165dabb5140ee2cc66b5137912ccd760",
        "email" => "user@mail.com",
        "family_name" => "LastName",
        "gender" => "male",
        "given_name" => "FirstName",
        "identities" => [
          {
            "access_token" => "ya29.AHES6ZRPK1Skc_rtB30Em_5RkZlKez3FkktcmJ_0RX5fIkCbkOCrXA",
            "provider" => "google-oauth2",
            "user_id" => "102835921788417079450",
            "connection" => "google-oauth2",
            "isSocial" => true
          }
        ],
        "locale" => "en",
        "name" => "FirstName LastName",
        "nickname" => "nick",
        "picture" => "pic",
        "user_id" => "google-oauth2|102835921788417079450"
      }
      allow(subject).to receive(:raw_info) { @raw_info }
    end

    context "info" do
      it 'returns the uid (required)' do
        expect(subject.uid).to eq('google-oauth2|102835921788417079450')
      end

      it 'returns the name (required)' do
        expect(subject.info[:name]).to eq('FirstName LastName')
      end

      it 'returns the email' do
        expect(subject.info[:email]).to eq('user@mail.com')
      end

      it 'returns the nickname' do
        expect(subject.info[:nickname]).to eq('nick')
      end

      it 'returns the last name' do
        expect(subject.info[:last_name]).to eq('LastName')
      end

      it 'returns the first name' do
        expect(subject.info[:first_name]).to eq('FirstName')
      end

      it 'returns the location' do
        expect(subject.info[:location]).to eq('en')
      end

      it 'returns the image' do
        expect(subject.info[:image]).to eq('pic')
      end
    end

    context "get token" do
      before :each do
        @access_token = double('OAuth2::AccessToken')

        allow(@access_token).to receive(:token)
        allow(@access_token).to receive(:expires?)
        allow(@access_token).to receive(:expires_at)
        allow(@access_token).to receive(:refresh_token)
        allow(@access_token).to receive(:params)

        allow(subject).to receive(:access_token) { @access_token }
      end

      it 'returns a Hash' do
        expect(subject.credentials).to be_a(Hash)
      end

      it 'returns the token' do
        allow(@access_token).to receive(:token) {
          {
            :access_token => "OTqSFa9zrh0VRGAZHH4QPJISCoynRwSy9FocUazuaU950EVcISsJo3pST11iTCiI",
            :token_type => "bearer"
          } }
        expect(subject.credentials['token'][:access_token]).to eq('OTqSFa9zrh0VRGAZHH4QPJISCoynRwSy9FocUazuaU950EVcISsJo3pST11iTCiI')
        expect(subject.credentials['token'][:token_type]).to eq('bearer')
      end
      
      it 'returns the refresh token' do
        allow(@access_token).to receive(:refresh_token) { "your_refresh_token" }
        allow(@access_token).to receive(:params) {
          {
            'id_token' => "your_id_token",
            'token_type' => "your_token_type"
          } }
        expect(subject.credentials['refresh_token']).to eq('your_refresh_token')
      end
    end
  end
end
