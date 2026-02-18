package com.userid.api.client;

public record AuthServerLoginRequest(
    String email,
    String password
) {
  public AuthServerLoginRequest {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
