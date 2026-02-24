package com.userid.api.client;

public record AuthServerLoginResponseDTO(
    String token,
    AuthServerLoginUserDTO user
) {}
