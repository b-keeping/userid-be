package com.userid.api.user;

public record UserLoginResponseDTO(
    String token,
    UserResponseDTO user
) {}
