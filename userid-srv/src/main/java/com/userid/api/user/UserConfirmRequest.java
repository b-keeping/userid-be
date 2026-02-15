package com.userid.api.user;

import jakarta.validation.constraints.NotBlank;

public record UserConfirmRequest(
    @NotBlank String code
) {}
