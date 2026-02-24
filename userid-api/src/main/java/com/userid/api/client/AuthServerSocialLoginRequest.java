package com.userid.api.client;

public record AuthServerSocialLoginRequest(
    String code,
    String codeVerifier,
    String deviceId,
    String state
) {}
