defmodule Ueberauth.Strategy.Vipps do
  @moduledoc """
  Vipps Strategy for Überauth.
  """

  use Ueberauth.Strategy,
    uid_field: :sub,
    default_scope: "api_version_2 openid name phoneNumber",
    userinfo_endpoint: "/vipps-userinfo-api/userinfo"

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles initial request for Vipps authentication.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)

    params =
      [scope: scopes]
      |> with_param(:state, conn)

    opts = oauth_client_options_from_conn(conn)
    redirect!(conn, Ueberauth.Strategy.Vipps.OAuth.authorize_url!(params, opts))
  end

  @doc """
  Handles the callback from Vipps.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code, "state" => state}} = conn) do
    params = [code: code]
    opts = oauth_client_options_from_conn(conn)

    case Ueberauth.Strategy.Vipps.OAuth.get_access_token(params, opts) do
      {:ok, token} ->
        conn
        |> put_private(:vipps_state, state)
        |> fetch_user(token)

      {:error, {error_code, error_description}} ->
        set_errors!(conn, [error(error_code, error_description)])
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:vipps_user, nil)
    |> put_private(:vipps_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.vipps_user[uid_field]
  end

  @doc """
  Includes the credentials from the vipps response.
  """
  def credentials(conn) do
    token = conn.private.vipps_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.vipps_user

    %Info{
      phone: user["phone_number"],
      email: user["email"],
      first_name: user["given_name"],
      last_name: user["family_name"],
      name: user["name"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the vipps callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.vipps_token,
        user: conn.private.vipps_user,
        state: conn.private.vipps_state,
        email_verified: conn.private.vipps_user["email_verified"]
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :vipps_token, token)

    path =
      case option(conn, :userinfo_endpoint) do
        {:system, varname, default} ->
          System.get_env(varname) || default

        {:system, varname} ->
          System.get_env(varname) || Keyword.get(default_options(), :userinfo_endpoint)

        other ->
          other
      end

    resp = Ueberauth.Strategy.Vipps.OAuth.get(token, path)

    case resp do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: user}} when status_code in 200..399 ->
        put_private(conn, :vipps_user, user)

      {:error, %OAuth2.Response{status_code: status_code}} ->
        set_errors!(conn, [error("OAuth2", status_code)])

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp with_param(opts, key, conn) do
    if value = conn.params[to_string(key)], do: Keyword.put(opts, key, value), else: opts
  end

  defp oauth_client_options_from_conn(conn) do
    base_options = [redirect_uri: callback_url(conn)]
    request_options = conn.private[:ueberauth_request_options].options

    case {request_options[:client_id], request_options[:client_secret]} do
      {nil, _} -> base_options
      {_, nil} -> base_options
      {id, secret} -> [client_id: id, client_secret: secret] ++ base_options
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
