package com.userid.api.serviceuser;

import com.userid.dal.entity.ServiceUserRole;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record ServiceUserRequest(
    @NotBlank String username,
    String password,
    @NotNull ServiceUserRole role,
    List<Long> domainIds
) {}
