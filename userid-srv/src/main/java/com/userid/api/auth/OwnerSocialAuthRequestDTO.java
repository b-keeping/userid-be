package com.userid.api.auth;

import jakarta.validation.constraints.NotBlank;

public record OwnerSocialAuthRequestDTO(
    @NotBlank String provider,
    @NotBlank String code,
    String codeVerifier,
    String deviceId,
    String state
) {
}
