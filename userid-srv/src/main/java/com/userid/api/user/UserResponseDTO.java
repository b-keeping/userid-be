package com.userid.api.user;

import java.time.OffsetDateTime;
import java.util.List;

public record UserResponseDTO(
    Long id,
    Long domainId,
    String email,
    boolean confirmed,
    boolean active,
    OffsetDateTime createdAt,
    List<UserProfileValueResponseDTO> values
) {}
