package com.userid.api.domain;

import jakarta.validation.constraints.NotBlank;

public record DomainRequest(
    @NotBlank String name,
    Long ownerId
) {}
