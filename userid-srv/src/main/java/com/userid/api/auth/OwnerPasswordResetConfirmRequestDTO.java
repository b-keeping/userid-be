package com.userid.api.auth;

import jakarta.validation.constraints.NotBlank;

public record OwnerPasswordResetConfirmRequestDTO(
    @NotBlank String token,
    @NotBlank String password
) {}
