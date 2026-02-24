package com.userid.api.domain;

import jakarta.validation.constraints.NotBlank;

public record DomainRequestDTO(
    @NotBlank String name,
    Long ownerId
) {}
