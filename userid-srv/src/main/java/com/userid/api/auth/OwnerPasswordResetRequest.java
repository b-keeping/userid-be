package com.userid.api.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;

public record OwnerPasswordResetRequest(
    @Email @NotBlank String email
) {
  public OwnerPasswordResetRequest {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
