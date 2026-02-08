package com.userid.service;

import com.userid.api.user.UserProfileFilterRequest;
import com.userid.api.user.UserProfileValueRequest;
import com.userid.api.user.UserProfileValueResponse;
import com.userid.api.user.UserRegistrationRequest;
import com.userid.api.user.UserResponse;
import com.userid.api.user.UserSearchRequest;
import com.userid.api.user.UserUpdateRequest;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.FieldType;
import com.userid.dal.entity.ProfileField;
import com.userid.dal.entity.User;
import com.userid.dal.entity.UserProfileValue;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.ProfileFieldRepository;
import com.userid.dal.repo.UserRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class UserService {
  private final DomainRepository domainRepository;
  private final ProfileFieldRepository profileFieldRepository;
  private final UserRepository userRepository;
  private final AccessService accessService;
  private final ObjectMapper objectMapper;
  private final PasswordEncoder passwordEncoder;
  private final EmailService emailService;
  private final UserOtpService userOtpService;

  @org.springframework.transaction.annotation.Transactional
  public UserResponse register(Long serviceUserId, Long domainId, UserRegistrationRequest request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    return registerInternal(domain, request);
  }

  @org.springframework.transaction.annotation.Transactional
  public UserResponse registerByDomain(Long domainId, UserRegistrationRequest request) {
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    return registerInternal(domain, request);
  }

  public UserResponse get(Long serviceUserId, Long domainId, Long userId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    User user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    return toResponse(user);
  }

  public List<UserResponse> search(Long serviceUserId, Long domainId, UserSearchRequest request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    if (!domainRepository.existsById(domainId)) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found");
    }
    List<UserProfileFilterRequest> filters = request == null || request.filters() == null
        ? List.of()
        : request.filters();

    Map<Long, ProfileField> fieldById = toFieldMap(profileFieldRepository.findByDomainId(domainId));
    List<UserSearchFilter> resolvedFilters = new ArrayList<>();

    for (UserProfileFilterRequest filter : filters) {
      if (filter.fieldId() == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Filter field id is required");
      }
      ProfileField field = fieldById.get(filter.fieldId());
      if (field == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown profile field id: " + filter.fieldId());
      }
      resolvedFilters.add(toSearchFilter(field, filter));
    }

    List<User> users = userRepository.searchByDomainAndFilters(domainId, resolvedFilters);
    return users.stream()
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public UserResponse update(Long serviceUserId, Long domainId, Long userId, UserUpdateRequest request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    User user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    return updateInternal(user, domainId, request, true);
  }

  public UserResponse updateByDomain(Long domainId, Long userId, UserUpdateRequest request) {
    User user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    return updateInternal(user, domainId, request, false);
  }

  public void delete(Long serviceUserId, Long domainId, Long userId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    User user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    userRepository.delete(user);
  }

  @org.springframework.transaction.annotation.Transactional
  private UserResponse registerInternal(Domain domain, UserRegistrationRequest request) {
    Long domainId = domain.getId();
    if (userRepository.existsByDomainIdAndEmail(domainId, request.email())) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists in domain");
    }

    User user = User.builder()
        .domain(domain)
        .email(request.email())
        .passwordHash(passwordEncoder.encode(requirePassword(request.password())))
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();

    applyProfileValues(user, domainId, request.values());
    User saved = userRepository.save(user);
    String otpCode = userOtpService.createVerificationCode(saved);
    emailService.sendOtpEmail(domain, saved.getEmail(), otpCode);
    return toResponse(saved);
  }

  private UserResponse updateInternal(User user, Long domainId, UserUpdateRequest request, boolean allowConfirmed) {
    if (!allowConfirmed && request.confirmed() != null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Confirmed flag is not allowed");
    }

    boolean emailChanged = false;
    if (request.password() != null && !request.password().isBlank()) {
      user.setPasswordHash(passwordEncoder.encode(request.password()));
    }
    if (request.email() != null && !request.email().isBlank()) {
      if (!request.email().equals(user.getEmail())
          && userRepository.existsByDomainIdAndEmail(domainId, request.email())) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists in domain");
      }
      if (!request.email().equals(user.getEmail())) {
        emailChanged = true;
      }
      user.setEmail(request.email());
    }

    if (allowConfirmed && request.confirmed() != null) {
      if (request.confirmed()) {
        user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
      } else {
        user.setEmailVerifiedAt(null);
        userOtpService.clearVerificationCode(user);
      }
    }

    if (request.values() != null) {
      applyProfileValues(user, domainId, request.values());
    }

    String otpCode = null;
    if (emailChanged && (!allowConfirmed || request.confirmed() == null || !request.confirmed())) {
      user.setEmailVerifiedAt(null);
      otpCode = userOtpService.createVerificationCode(user);
    }

    User saved = userRepository.save(user);
    if (otpCode != null) {
      emailService.sendOtpEmail(user.getDomain(), saved.getEmail(), otpCode);
    }
    return toResponse(saved);
  }

  private Map<Long, ProfileField> toFieldMap(List<ProfileField> fields) {
    Map<Long, ProfileField> fieldById = new HashMap<>();
    for (ProfileField field : fields) {
      fieldById.put(field.getId(), field);
    }
    return fieldById;
  }

  void applyProfileValues(User user, Long domainId, List<UserProfileValueRequest> requests) {
    List<ProfileField> fields = profileFieldRepository.findByDomainId(domainId);
    Map<Long, ProfileField> fieldById = toFieldMap(fields);
    List<UserProfileValueRequest> valueRequests = requests == null ? List.of() : requests;

    Set<Long> providedFieldIds = new HashSet<>();
    List<UserProfileValue> values = new ArrayList<>();
    List<Long> unknownFieldIds = new ArrayList<>();

    for (UserProfileValueRequest valueRequest : valueRequests) {
      Long fieldId = valueRequest.fieldId();
      if (fieldId == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Profile field id is required");
      }
      ProfileField field = fieldById.get(fieldId);
      if (field == null) {
        unknownFieldIds.add(fieldId);
        continue;
      }
      if (!providedFieldIds.add(fieldId)) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Duplicate profile field id: " + fieldId);
      }

      UserProfileValue value = new UserProfileValue();
      value.setField(field);
      applyValue(value, field.getType(), valueRequest);
      values.add(value);
    }

    if (!unknownFieldIds.isEmpty()) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST,
          "Unknown profile field id(s): " + unknownFieldIds.stream().map(String::valueOf).collect(Collectors.joining(", "))
      );
    }

    List<String> missingMandatory = fields.stream()
        .filter(field -> field.isMandatory() && !providedFieldIds.contains(field.getId()))
        .map(ProfileField::getName)
        .toList();

    if (!missingMandatory.isEmpty()) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST,
          "Missing mandatory fields: " + String.join(", ", missingMandatory)
      );
    }

    user.getValues().clear();
    for (UserProfileValue value : values) {
      value.setUser(user);
      user.getValues().add(value);
    }

    user.setProfileJsonb(serializeProfile(values));
  }

  private void applyValue(UserProfileValue value, FieldType type, UserProfileValueRequest request) {
    switch (type) {
      case STRING -> {
        requireValue(request.stringValue(), "stringValue");
        value.setValueString(request.stringValue());
      }
      case BOOLEAN -> {
        requireValue(request.booleanValue(), "booleanValue");
        value.setValueBoolean(request.booleanValue());
      }
      case INTEGER -> {
        requireValue(request.integerValue(), "integerValue");
        value.setValueInteger(request.integerValue());
      }
      case DECIMAL -> {
        requireValue(request.decimalValue(), "decimalValue");
        value.setValueDecimal(request.decimalValue());
      }
      case DATE -> {
        requireValue(request.dateValue(), "dateValue");
        value.setValueDate(request.dateValue());
      }
      case TIME -> {
        requireValue(request.timeValue(), "timeValue");
        value.setValueTime(request.timeValue());
      }
      case TIMESTAMP -> {
        requireValue(request.timestampValue(), "timestampValue");
        value.setValueTimestamp(request.timestampValue());
      }
    }
  }

  private UserSearchFilter toSearchFilter(ProfileField field, UserProfileFilterRequest request) {
    return switch (field.getType()) {
      case STRING -> new UserSearchFilter(field.getId(), field.getType(),
          requireValue(request.stringValue(), "stringValue"), null, null, null, null, null, null);
      case BOOLEAN -> new UserSearchFilter(field.getId(), field.getType(),
          null, requireValue(request.booleanValue(), "booleanValue"), null, null, null, null, null);
      case INTEGER -> new UserSearchFilter(field.getId(), field.getType(),
          null, null, requireValue(request.integerValue(), "integerValue"), null, null, null, null);
      case DECIMAL -> new UserSearchFilter(field.getId(), field.getType(),
          null, null, null, requireValue(request.decimalValue(), "decimalValue"), null, null, null);
      case DATE -> new UserSearchFilter(field.getId(), field.getType(),
          null, null, null, null, requireValue(request.dateValue(), "dateValue"), null, null);
      case TIME -> new UserSearchFilter(field.getId(), field.getType(),
          null, null, null, null, null, requireValue(request.timeValue(), "timeValue"), null);
      case TIMESTAMP -> new UserSearchFilter(field.getId(), field.getType(),
          null, null, null, null, null, null, requireValue(request.timestampValue(), "timestampValue"));
    };
  }

  UserResponse toResponse(User user) {
    List<UserProfileValueResponse> values = parseProfile(user.getProfileJsonb());
    if (values == null) {
      values = user.getValues().stream()
          .sorted(Comparator
              .comparing((UserProfileValue v) -> v.getField().getSortOrder(), Comparator.nullsLast(Integer::compareTo))
              .thenComparing(v -> v.getField().getId()))
          .map(this::toResponse)
          .collect(Collectors.toList());
    }

    boolean confirmed = user.getEmailVerifiedAt() != null;
    return new UserResponse(user.getId(), user.getEmail(), confirmed, user.getCreatedAt(), values);
  }

  private UserProfileValueResponse toResponse(UserProfileValue value) {
    ProfileField field = value.getField();
    return new UserProfileValueResponse(
        field.getId(),
        field.getName(),
        field.getType(),
        field.isMandatory(),
        value.getValueString(),
        value.getValueBoolean(),
        value.getValueInteger(),
        value.getValueDecimal(),
        value.getValueDate(),
        value.getValueTime(),
        value.getValueTimestamp()
    );
  }

  private static <T> T requireValue(T value, String name) {
    if (value == null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing value for " + name);
    }
    if (value instanceof String stringValue && stringValue.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing value for " + name);
    }
    return value;
  }

  private static String requirePassword(String password) {
    if (password == null || password.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
    }
    return password;
  }

  private JsonNode serializeProfile(List<UserProfileValue> values) {
    List<UserProfileValueResponse> snapshot = values.stream()
        .sorted(Comparator
            .comparing((UserProfileValue v) -> v.getField().getSortOrder(), Comparator.nullsLast(Integer::compareTo))
            .thenComparing(v -> v.getField().getId()))
        .map(this::toResponse)
        .collect(Collectors.toList());
    return objectMapper.valueToTree(snapshot);
  }

  private List<UserProfileValueResponse> parseProfile(JsonNode json) {
    if (json == null || json.isNull() || json.isMissingNode()) {
      return List.of();
    }
    if (json.isObject() && json.isEmpty()) {
      return List.of();
    }
    if (!json.isArray()) {
      return null;
    }
    try {
      return objectMapper.convertValue(json, new TypeReference<List<UserProfileValueResponse>>() {});
    } catch (Exception ex) {
      return null;
    }
  }
}
