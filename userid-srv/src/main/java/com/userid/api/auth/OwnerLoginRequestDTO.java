package com.userid.api.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;

public record OwnerLoginRequestDTO(
    @Email @NotBlank String email,
    @NotBlank String password
) {
  public OwnerLoginRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
