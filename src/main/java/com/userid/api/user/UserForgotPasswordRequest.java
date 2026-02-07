package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UserForgotPasswordRequest(
    @Email @NotBlank String email
) {}
