package com.userid.api.client;

import java.util.List;

public record AuthServerRegisterRequest(
    String email,
    String password,
    List<AuthServerProfileValue> values
) {
  public AuthServerRegisterRequest {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
