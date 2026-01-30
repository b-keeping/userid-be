package com.userid.api.serviceuser;

import jakarta.validation.constraints.NotNull;

public record ServiceUserDomainRequest(
    @NotNull Long domainId
) {}
