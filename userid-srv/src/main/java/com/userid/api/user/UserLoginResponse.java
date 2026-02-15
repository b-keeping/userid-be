package com.userid.api.user;

public record UserLoginResponse(
    String token,
    UserAuthResponse user
) {}
