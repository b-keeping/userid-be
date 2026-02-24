package com.userid.api.user;

import jakarta.validation.constraints.Email;
import com.userid.api.client.EmailNormalizer;
import java.util.List;

public record UserUpdateRequestDTO(
    String password,
    @Email String email,
    List<UserProfileValueRequestDTO> values,
    Boolean confirmed
) {
  public UserUpdateRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
