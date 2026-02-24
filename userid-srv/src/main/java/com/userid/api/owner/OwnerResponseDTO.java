package com.userid.api.owner;

import com.userid.dal.entity.OwnerRoleEnum;
import java.time.OffsetDateTime;
import java.util.List;

public record OwnerResponseDTO(
    Long id,
    String email,
    OwnerRoleEnum role,
    OffsetDateTime createdAt,
    List<Long> domainIds
) {}
