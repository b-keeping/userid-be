package com.userid.api.serviceuser;

import com.userid.dal.entity.ServiceUserRole;
import java.time.OffsetDateTime;
import java.util.List;

public record ServiceUserResponse(
    Long id,
    String username,
    ServiceUserRole role,
    OffsetDateTime createdAt,
    List<Long> domainIds
) {}
