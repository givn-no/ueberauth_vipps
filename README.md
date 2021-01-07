# Überauth Vipps

> Vipps OAuth2 strategy for Überauth.

## Installation

1. Setup your application at [portal.vipps.no](https://portal.vipps.no).

1. Add `:ueberauth_vipps` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_vipps, "~> 0.1"}]
    end
    ```

1. Add the strategy to your applications:

    ```elixir
    def application do
      [applications: [:ueberauth_vipps]]
    end
    ```

1. Add Vipps to your Überauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        vipps: {Ueberauth.Strategy.Vipps, []}
      ]
    ```

1.  Update your provider configuration:

    Use that if you want to read client ID/secret from the environment
    variables in the compile time:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.Vipps.OAuth,
      client_id: System.get_env("VIPPS_CLIENT_ID"),
      client_secret: System.get_env("VIPPS_CLIENT_SECRET")
    ```

    Use that if you want to read client ID/secret from the environment
    variables in the run time:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.Vipps.OAuth,
      client_id: {System, :get_env, ["VIPPS_CLIENT_ID"]},
      client_secret: {System, :get_env, ["VIPPS_CLIENT_SECRET"]}
    ```

1.  Include the Überauth plug in your controller:

    ```elixir
    defmodule MyApp.AuthController do
      use MyApp.Web, :controller
      plug Ueberauth
      ...
    end
    ```

1.  Create the request and callback routes if you haven't already:

    ```elixir
    scope "/auth", MyApp do
      pipe_through :browser

      get "/:provider", AuthController, :request
      get "/:provider/callback", AuthController, :callback
    end
    ```

1. Your controller needs to implement callbacks to deal with `Ueberauth.Auth` and `Ueberauth.Failure` responses.

For an example implementation see the [Überauth Example](https://github.com/ueberauth/ueberauth_example) application.

## Calling

Depending on the configured url you can initiate the request through:

    /auth/vipps

Or with options:

    /auth/vipps?scope=email%20profile

By default the requested scope is "phoneNumber". Scope can be configured either explicitly as a `scope` query value on the request path or in your configuration:

```elixir
config :ueberauth, Ueberauth,
  providers: [
    vipps: {Ueberauth.Strategy.Vipps, [default_scope: "email phoneNumber name"]}
  ]
```


To guard against client-side request modification, it's important to still check the domain in `info.urls[:website]` within the `Ueberauth.Auth` struct if you want to limit sign-in to a specific domain.

## License

Please see [LICENSE](https://github.com/hoopla/ueberauth_vipps/blob/master/LICENSE) for licensing details.
