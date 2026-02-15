package com.userid.api.owner;

import com.userid.dal.entity.OwnerRole;
import jakarta.validation.constraints.Email;
import java.util.List;

public record OwnerUpdateRequest(
    @Email String email,
    String password,
    OwnerRole role,
    List<Long> domainIds
) {}
