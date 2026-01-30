package com.userid.api.auth;

import jakarta.validation.constraints.NotBlank;

public record ServiceLoginRequest(
    @NotBlank String username,
    @NotBlank String password
) {}
