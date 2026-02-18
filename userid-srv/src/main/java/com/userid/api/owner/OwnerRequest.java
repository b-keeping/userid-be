package com.userid.api.owner;

import com.userid.dal.entity.OwnerRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import com.userid.api.client.EmailNormalizer;
import java.util.List;

public record OwnerRequest(
    @Email @NotBlank String email,
    String password,
    @NotNull OwnerRole role,
    List<Long> domainIds
) {
  public OwnerRequest {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
