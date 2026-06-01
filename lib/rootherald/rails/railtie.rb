# frozen_string_literal: true

require "rails/railtie"
require_relative "controller_concern"

module RootHerald
  # Rails autoload hook: makes +RootHerald::Guard+ available to controllers
  # without requiring +require_relative+ in every initializer. Opt-in —
  # require +rootherald/rails/railtie+ from your app to activate.
  class Railtie < ::Rails::Railtie
    initializer "rootherald.guard" do |_app|
      ActiveSupport.on_load(:action_controller) do
        # No-op include — controllers that want the guard say so explicitly
        # with `include RootHerald::Guard`.
      end
    end
  end
end
