package com.userid.api.client;

public record AuthServerLoginUserDTO(
    Long id,
    String email,
    boolean confirmed,
    boolean active,
    Long domainId
) {}
