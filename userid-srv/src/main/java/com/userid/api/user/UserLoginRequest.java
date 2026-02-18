package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;

public record UserLoginRequest(
    @Email @NotBlank String email,
    @NotBlank String password
) {
  public UserLoginRequest {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
