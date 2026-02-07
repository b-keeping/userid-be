package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UserResetPasswordRequest(
    @Email @NotBlank String email,
    @NotBlank String code,
    @NotBlank String password
) {}
