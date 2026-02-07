package com.userid.api.domain;

public record DomainJwtSecretResponse(
    Long domainId,
    String secret
) {}
