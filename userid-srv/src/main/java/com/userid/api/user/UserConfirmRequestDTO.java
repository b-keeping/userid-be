package com.userid.api.user;

import jakarta.validation.constraints.NotBlank;

public record UserConfirmRequestDTO(
    @NotBlank String code
) {}
