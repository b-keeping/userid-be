package com.userid.api.client;

public record AuthServerSocialAuthRequestDTO(
    String provider,
    String code,
    String codeVerifier,
    String deviceId,
    String state
) {
}
