package com.userid.api.user;

import jakarta.validation.constraints.NotBlank;

public record UserResetPasswordRequestDTO(
    @NotBlank String code,
    @NotBlank String password
) {}
