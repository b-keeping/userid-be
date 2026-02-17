package com.userid.api.auth;

import jakarta.validation.constraints.NotBlank;

public record OwnerSocialAuthRequest(
    @NotBlank String provider,
    @NotBlank String code
) {
}
