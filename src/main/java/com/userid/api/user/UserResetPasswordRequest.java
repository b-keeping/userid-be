package com.userid.api.user;

import jakarta.validation.constraints.NotBlank;

public record UserResetPasswordRequest(
    @NotBlank String code,
    @NotBlank String password
) {}
