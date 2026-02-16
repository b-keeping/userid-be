package com.userid.api.client;

public record DomainSocialProviderConfigRequest(
    Boolean enabled,
    String clientId,
    String clientSecret,
    String callbackUri
) {}
