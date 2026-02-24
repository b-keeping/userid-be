package com.userid.api.client;

public record AuthServerLoginRequestDTO(
    String email,
    String password
) {
  public AuthServerLoginRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
