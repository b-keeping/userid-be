package com.userid.api.domain;

import java.time.OffsetDateTime;

public record DomainApiTokenResponseDTO(String token, OffsetDateTime expiresAt) {}
