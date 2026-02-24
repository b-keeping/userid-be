package com.userid.api.owner;

import com.userid.dal.entity.OwnerRoleEnum;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import com.userid.api.client.EmailNormalizer;
import java.util.List;

public record OwnerRequestDTO(
    @Email @NotBlank String email,
    String password,
    @NotNull OwnerRoleEnum role,
    List<Long> domainIds
) {
  public OwnerRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
