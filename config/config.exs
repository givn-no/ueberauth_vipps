use Mix.Config

config :ueberauth, Ueberauth,
  providers: [
    vipps: {Ueberauth.Strategy.Vipps, []}
  ]

config :ueberauth, Ueberauth.Strategy.Vipps.OAuth,
  client_id: "client_id",
  client_secret: "client_secret",
  token_url: "token_url"
