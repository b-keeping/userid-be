package com.userid.api.owner;

import com.userid.dal.entity.OwnerRoleEnum;
import jakarta.validation.constraints.Email;
import com.userid.api.client.EmailNormalizer;
import java.util.List;

public record OwnerUpdateRequestDTO(
    @Email String email,
    String password,
    OwnerRoleEnum role,
    List<Long> domainIds
) {
  public OwnerUpdateRequestDTO {
    email = EmailNormalizer.normalizeNullable(email);
  }
}
