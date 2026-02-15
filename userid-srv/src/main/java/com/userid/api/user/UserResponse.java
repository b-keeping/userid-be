package com.userid.api.user;

import java.time.OffsetDateTime;
import java.util.List;

public record UserResponse(
    Long id,
    String email,
    boolean confirmed,
    OffsetDateTime createdAt,
    List<UserProfileValueResponse> values
) {}
