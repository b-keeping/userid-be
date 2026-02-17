package com.userid.api.client;

public record AuthServerSocialAuthRequest(
    String provider,
    String code
) {
}
