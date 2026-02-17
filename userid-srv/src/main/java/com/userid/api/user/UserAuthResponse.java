package com.userid.api.user;

import java.time.OffsetDateTime;

public record UserAuthResponse(
    Long id,
    Long domainId,
    String email,
    boolean confirmed,
    boolean active,
    OffsetDateTime createdAt
) {}
