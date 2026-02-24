package com.userid.api.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;

public record OwnerPasswordResetRequestDTO(
    @Email @NotBlank String email
) {
  public OwnerPasswordResetRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
