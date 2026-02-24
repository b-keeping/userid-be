package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;

public record UserForgotPasswordRequestDTO(
    @Email @NotBlank String email
) {
  public UserForgotPasswordRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
