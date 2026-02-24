package com.userid.api.client;

public record DomainSocialProviderConfigRequestDTO(
    Boolean enabled,
    String clientId,
    String clientSecret,
    String callbackUri
) {}
