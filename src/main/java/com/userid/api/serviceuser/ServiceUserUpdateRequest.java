package com.userid.api.serviceuser;

import com.userid.dal.entity.ServiceUserRole;
import java.util.List;

public record ServiceUserUpdateRequest(
    String username,
    String password,
    ServiceUserRole role,
    List<Long> domainIds
) {}
