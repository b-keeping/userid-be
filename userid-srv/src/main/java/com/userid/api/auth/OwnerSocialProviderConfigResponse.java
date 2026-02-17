package com.userid.api.auth;

public record OwnerSocialProviderConfigResponse(
    String provider,
    boolean enabled,
    String clientId,
    String callbackUri
) {
}
