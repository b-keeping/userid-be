package com.userid.api.auth;

import jakarta.validation.constraints.NotBlank;

public record OwnerLoginRequest(
    @NotBlank String username,
    @NotBlank String password
) {}
