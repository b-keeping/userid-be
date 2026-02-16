package com.userid.api.client;

public record DomainSocialProviderConfigResponse(
    String provider,
    Boolean enabled,
    String clientId,
    Boolean clientSecretConfigured,
    String callbackUri
) {}
