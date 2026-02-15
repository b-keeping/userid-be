package com.userid.api.client;

public record AuthServerLoginResponse(
    String token,
    AuthServerLoginUser user
) {}
