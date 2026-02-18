package com.userid.api.client;

public record AuthServerForgotPasswordRequest(
    String email
) {
  public AuthServerForgotPasswordRequest {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
