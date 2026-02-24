package com.userid.api.client;

public record AuthServerForgotPasswordRequestDTO(
    String email
) {
  public AuthServerForgotPasswordRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
