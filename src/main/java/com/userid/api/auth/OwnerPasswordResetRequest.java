package com.userid.api.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record OwnerPasswordResetRequest(
    @Email @NotBlank String email
) {}
