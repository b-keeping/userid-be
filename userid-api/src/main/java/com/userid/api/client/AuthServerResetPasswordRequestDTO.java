package com.userid.api.client;

public record AuthServerResetPasswordRequestDTO(
    String code,
    String password
) {
}
