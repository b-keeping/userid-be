package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;
import java.util.List;

public record UserRegistrationRequest(
    @Email @NotBlank String email,
    @NotBlank String password,
    List<UserProfileValueRequest> values
) {
  public UserRegistrationRequest {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
