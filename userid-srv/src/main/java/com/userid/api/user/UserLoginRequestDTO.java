package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;

public record UserLoginRequestDTO(
    @Email @NotBlank String email,
    @NotBlank String password
) {
  public UserLoginRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
