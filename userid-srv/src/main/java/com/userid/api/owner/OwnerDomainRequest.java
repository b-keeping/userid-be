package com.userid.api.owner;

import jakarta.validation.constraints.NotNull;

public record OwnerDomainRequest(
    @NotNull Long domainId
) {}
