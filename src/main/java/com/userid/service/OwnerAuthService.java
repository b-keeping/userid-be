package com.userid.service;

import com.userid.api.auth.OwnerLoginRequest;
import com.userid.api.auth.OwnerLoginResponse;
import com.userid.api.owner.OwnerResponse;
import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerRole;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import com.userid.security.JwtService;
import java.util.Collections;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OwnerAuthService {
  private final OwnerRepository ownerRepository;
  private final OwnerDomainRepository ownerDomainRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;

  public OwnerAuthService(
      OwnerRepository ownerRepository,
      OwnerDomainRepository ownerDomainRepository,
      PasswordEncoder passwordEncoder,
      JwtService jwtService
  ) {
    this.ownerRepository = ownerRepository;
    this.ownerDomainRepository = ownerDomainRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtService = jwtService;
  }

  public OwnerLoginResponse login(OwnerLoginRequest request) {
    Owner user = ownerRepository.findByUsername(request.username())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }

    String token = jwtService.generateToken(user);
    return new OwnerLoginResponse(token, toResponse(user));
  }

  private OwnerResponse toResponse(Owner user) {
    List<Long> domainIds;
    if (user.getRole() == OwnerRole.ADMIN) {
      domainIds = Collections.emptyList();
    } else {
      domainIds = ownerDomainRepository.findByOwnerId(user.getId()).stream()
          .map(link -> link.getDomain().getId())
          .distinct()
          .toList();
    }

    return new OwnerResponse(
        user.getId(),
        user.getUsername(),
        user.getRole(),
        user.getCreatedAt(),
        domainIds
    );
  }
}
