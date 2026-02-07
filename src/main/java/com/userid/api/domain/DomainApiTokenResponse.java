package com.userid.api.domain;

import java.time.OffsetDateTime;

public record DomainApiTokenResponse(String token, OffsetDateTime expiresAt) {}
