package com.userid.api.auth;

import jakarta.validation.constraints.NotBlank;

public record OwnerPasswordResetConfirmRequest(
    @NotBlank String token,
    @NotBlank String password
) {}
