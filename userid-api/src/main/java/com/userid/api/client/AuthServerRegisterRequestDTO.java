package com.userid.api.client;

import java.util.List;

public record AuthServerRegisterRequestDTO(
    String email,
    String password,
    List<AuthServerProfileValueDTO> values
) {
  public AuthServerRegisterRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
