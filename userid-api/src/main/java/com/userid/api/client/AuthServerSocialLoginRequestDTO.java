package com.userid.api.client;

public record AuthServerSocialLoginRequestDTO(
    String code,
    String codeVerifier,
    String deviceId,
    String state
) {}
