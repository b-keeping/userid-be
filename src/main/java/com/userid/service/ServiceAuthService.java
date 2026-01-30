package com.userid.service;

import com.userid.api.auth.ServiceLoginRequest;
import com.userid.api.auth.ServiceLoginResponse;
import com.userid.api.serviceuser.ServiceUserResponse;
import com.userid.dal.entity.ServiceUser;
import com.userid.dal.entity.ServiceUserRole;
import com.userid.dal.repo.ServiceUserDomainRepository;
import com.userid.dal.repo.ServiceUserRepository;
import com.userid.security.JwtService;
import java.util.Collections;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class ServiceAuthService {
  private final ServiceUserRepository serviceUserRepository;
  private final ServiceUserDomainRepository serviceUserDomainRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;

  public ServiceAuthService(
      ServiceUserRepository serviceUserRepository,
      ServiceUserDomainRepository serviceUserDomainRepository,
      PasswordEncoder passwordEncoder,
      JwtService jwtService
  ) {
    this.serviceUserRepository = serviceUserRepository;
    this.serviceUserDomainRepository = serviceUserDomainRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtService = jwtService;
  }

  public ServiceLoginResponse login(ServiceLoginRequest request) {
    ServiceUser user = serviceUserRepository.findByUsername(request.username())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }

    String token = jwtService.generateToken(user);
    return new ServiceLoginResponse(token, toResponse(user));
  }

  private ServiceUserResponse toResponse(ServiceUser user) {
    List<Long> domainIds;
    if (user.getRole() == ServiceUserRole.ADMIN) {
      domainIds = Collections.emptyList();
    } else {
      domainIds = serviceUserDomainRepository.findByServiceUserId(user.getId()).stream()
          .map(link -> link.getDomain().getId())
          .distinct()
          .toList();
    }

    return new ServiceUserResponse(
        user.getId(),
        user.getUsername(),
        user.getRole(),
        user.getCreatedAt(),
        domainIds
    );
  }
}
