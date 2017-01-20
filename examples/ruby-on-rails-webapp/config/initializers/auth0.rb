Rails.application.config.middleware.use OmniAuth::Builder do
  provider(
    :auth0,
    client_id: ENV["AUTH0_CLIENT_ID"],
    client_secret: ENV["AUTH0_CLIENT_SECRET"],
    namespace: ENV["AUTH0_DOMAIN"],
    callback_path: "/auth/auth0/callback"
  )
end
