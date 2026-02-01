package com.userid.api.owner;

import com.userid.dal.entity.OwnerRole;
import java.time.OffsetDateTime;
import java.util.List;

public record OwnerResponse(
    Long id,
    String email,
    OwnerRole role,
    OffsetDateTime createdAt,
    List<Long> domainIds
) {}
