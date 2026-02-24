package com.userid.api.auth;

public record OwnerSocialProviderConfigResponseDTO(
    String provider,
    boolean enabled,
    String clientId,
    String callbackUri
) {
}
