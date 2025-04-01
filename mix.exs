defmodule UeberauthVipps.Mixfile do
  use Mix.Project

  @version "0.1.1"
  @url "https://github.com/givn-no/ueberauth_vipps"

  def project do
    [
      app: :ueberauth_vipps,
      version: @version,
      name: "Ueberauth Vipps Strategy",
      package: package(),
      hex: hex(),
      elixir: "~> 1.3",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      source_url: @url,
      homepage_url: @url,
      description: description(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [applications: [:logger, :oauth2, :ueberauth]]
  end

  defp deps do
    [
      {:oauth2, "~> 1.0 or ~> 2.0"},
      {:ueberauth, "~> 0.7"},
      {:credo, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: [:dev], runtime: false},
      {:mock, "~> 0.3", only: :test}
    ]
  end

  defp docs do
    [extras: ["README.md", "CONTRIBUTING.md"]]
  end

  defp description do
    "An Uberauth strategy for Vipps authentication."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Lars Rasmussen"],
      licenses: ["MIT"],
      links: %{GitHub: @url}
    ]
  end

  defp hex do
    [
      api_url: System.get_env("HEX_API_URL"),
      api_key: System.get_env("HEX_API_KEY")
    ]
  end
end
