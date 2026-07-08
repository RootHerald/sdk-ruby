# frozen_string_literal: true

require "rootherald"

RSpec.configure do |c|
  c.expect_with :rspec do |e|
    e.syntax = :expect
  end
  c.filter_run_when_matching :focus
  c.example_status_persistence_file_path = ".rspec_status"
  c.disable_monkey_patching!
end
