# frozen_string_literal: true

require_relative "lib/rootherald/version"

Gem::Specification.new do |spec|
  spec.name = "rootherald"
  spec.version = RootHerald::VERSION
  spec.authors = ["Root Herald"]
  spec.email = ["hello@rootherald.io"]

  spec.summary = "Root Herald server SDK for Ruby."
  spec.description = "Verifies Root Herald attestation tokens (JWTs) and CAEP " \
    "webhook Security Event Tokens (SET JWTs)."
  spec.homepage = "https://rootherald.io"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/RootHerald/sdk-ruby"
  spec.metadata["documentation_uri"] = "https://rootherald.io/developers/sdks/ruby"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*.rb",
    "README.md",
    "LICENSE",
    "rootherald.gemspec"
  ]
  spec.require_paths = ["lib"]

  spec.add_dependency "faraday", "~> 2.7"
  spec.add_dependency "jwt", "~> 2.7"
end
