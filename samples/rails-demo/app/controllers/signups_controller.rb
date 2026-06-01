# frozen_string_literal: true

class SignupsController < ApplicationController
  include RootHerald::Guard
  guard_device :create, action: "signup"

  def create
    # rootherald_claims contains the verified AttestationClaims object.
    user = User.create!(signup_params.merge(device_id: rootherald_claims.device_id))
    render json: { id: user.id }, status: :created
  end

  private

  def signup_params
    params.require(:user).permit(:email, :name)
  end
end
