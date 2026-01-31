package com.userid.api.owner;

import com.userid.dal.entity.OwnerRole;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record OwnerRequest(
    @NotBlank String username,
    String password,
    @NotNull OwnerRole role,
    List<Long> domainIds
) {}
