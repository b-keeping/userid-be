package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.userid.api.client.EmailNormalizer;
import java.util.List;

public record UserRegistrationRequestDTO(
    @Email @NotBlank String email,
    @NotBlank String password,
    List<UserProfileValueRequestDTO> values
) {
  public UserRegistrationRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
