package com.userid.api.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UserConfirmRequest(
    @Email @NotBlank String email,
    @NotBlank String code
) {}
