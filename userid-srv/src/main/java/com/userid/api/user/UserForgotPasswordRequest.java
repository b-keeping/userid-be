package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;

public record UserForgotPasswordRequest(
    @Email @NotBlank String email
) {
  public UserForgotPasswordRequest {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
