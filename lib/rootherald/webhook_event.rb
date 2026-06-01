# frozen_string_literal: true

module RootHerald
  # Decoded CAEP Security Event Token envelope. The SET carries exactly
  # one event; that event's type URI and body are exposed via
  # +event_type+ and +event_payload+.
  class WebhookEvent
    attr_reader :issuer, :audience, :issued_at, :jwt_id,
                :subject_id_format, :device_id,
                :event_type, :event_payload, :raw

    def initialize(**kwargs)
      kwargs.each { |k, v| instance_variable_set(:"@#{k}", v) }
      freeze
    end
  end
end
