package com.userid.api.client;

public record AuthServerLoginRequest(
    String email,
    String password
) {}
