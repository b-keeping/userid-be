package com.userid.api.client;

public record AuthServerResetPasswordRequest(
    String code,
    String password
) {
}
