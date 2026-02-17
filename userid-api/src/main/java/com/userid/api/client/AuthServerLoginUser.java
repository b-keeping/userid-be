package com.userid.api.client;

public record AuthServerLoginUser(
    Long id,
    String email,
    boolean confirmed,
    boolean active,
    Long domainId
) {}
