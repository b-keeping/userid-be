package com.userid.security;

import com.userid.dal.entity.ServiceUserRole;

public record AuthPrincipal(Long id, String username, ServiceUserRole role) {
}
