package com.userid.api.client;

public record DomainSocialProviderConfigResponseDTO(
    String provider,
    Boolean enabled,
    String clientId,
    Boolean clientSecretConfigured,
    String callbackUri
) {}
