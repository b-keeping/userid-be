package com.userid.api.user;

import java.time.OffsetDateTime;

public record UserAuthResponseDTO(
    Long id,
    Long domainId,
    String email,
    boolean confirmed,
    boolean active,
    OffsetDateTime createdAt
) {}
