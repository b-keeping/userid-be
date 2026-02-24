package com.userid.api.owner;

import jakarta.validation.constraints.NotNull;

public record OwnerDomainRequestDTO(
    @NotNull Long domainId
) {}
