package com.userid.service;

import com.userid.api.user.UserProfileFilterRequest;
import com.userid.api.user.UserProfileValueRequest;
import com.userid.api.user.UserProfileValueResponse;
import com.userid.api.user.UserRegistrationRequest;
import com.userid.api.user.UserResponse;
import com.userid.api.user.UserSearchRequest;
import com.userid.api.user.UserUpdateRequest;
import com.fasterxml.jackson.core.type.TypeReference;
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

  public UserResponse register(Long serviceUserId, Long domainId, UserRegistrationRequest request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    List<ProfileField> fields = profileFieldRepository.findByDomainId(domainId);
    Map<Long, ProfileField> fieldById = toFieldMap(fields);

    List<UserProfileValueRequest> valueRequests =
        request.values() == null ? List.of() : request.values();

    Set<Long> providedFieldIds = new HashSet<>();
    List<UserProfileValue> values = new ArrayList<>();

    for (UserProfileValueRequest valueRequest : valueRequests) {
      Long fieldId = valueRequest.fieldId();
      if (fieldId == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Profile field id is required");
      }
      ProfileField field = fieldById.get(fieldId);
      if (field == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown profile field id: " + fieldId);
      }
      if (!providedFieldIds.add(fieldId)) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Duplicate profile field id: " + fieldId);
      }

      UserProfileValue value = new UserProfileValue();
      value.setField(field);
      applyValue(value, field.getType(), valueRequest);
      values.add(value);
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

    User user = User.builder()
        .domain(domain)
        .login(request.login())
        .email(request.email())
        .passwordHash(passwordEncoder.encode(requirePassword(request.password())))
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();

    for (UserProfileValue value : values) {
      value.setUser(user);
      user.getValues().add(value);
    }

    user.setProfileJsonb(serializeProfile(values));

    User saved = userRepository.save(user);
    return toResponse(saved);
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

    if (request.login() != null && !request.login().isBlank()) {
      if (!request.login().equals(user.getLogin())
          && userRepository.existsByDomainIdAndLogin(domainId, request.login())) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Login already exists in domain");
      }
      user.setLogin(request.login());
    }
    if (request.password() != null && !request.password().isBlank()) {
      user.setPasswordHash(passwordEncoder.encode(request.password()));
    }
    if (request.email() != null) {
      user.setEmail(request.email());
    }

    if (request.values() != null) {
      List<ProfileField> fields = profileFieldRepository.findByDomainId(domainId);
      Map<Long, ProfileField> fieldById = toFieldMap(fields);

      Set<Long> providedFieldIds = new HashSet<>();
      List<UserProfileValue> values = new ArrayList<>();

      for (UserProfileValueRequest valueRequest : request.values()) {
        Long fieldId = valueRequest.fieldId();
        if (fieldId == null) {
          throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Profile field id is required");
        }
        ProfileField field = fieldById.get(fieldId);
        if (field == null) {
          throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown profile field id: " + fieldId);
        }
        if (!providedFieldIds.add(fieldId)) {
          throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Duplicate profile field id: " + fieldId);
        }

        UserProfileValue value = new UserProfileValue();
        value.setField(field);
        applyValue(value, field.getType(), valueRequest);
        values.add(value);
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

    User saved = userRepository.save(user);
    return toResponse(saved);
  }

  public void delete(Long serviceUserId, Long domainId, Long userId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    User user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    userRepository.delete(user);
  }

  private Map<Long, ProfileField> toFieldMap(List<ProfileField> fields) {
    Map<Long, ProfileField> fieldById = new HashMap<>();
    for (ProfileField field : fields) {
      fieldById.put(field.getId(), field);
    }
    return fieldById;
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

  private UserResponse toResponse(User user) {
    List<UserProfileValueResponse> values = parseProfile(user.getProfileJsonb());
    if (values == null) {
      values = user.getValues().stream()
          .sorted(Comparator
              .comparing((UserProfileValue v) -> v.getField().getSortOrder(), Comparator.nullsLast(Integer::compareTo))
              .thenComparing(v -> v.getField().getId()))
          .map(this::toResponse)
          .collect(Collectors.toList());
    }

    return new UserResponse(user.getId(), user.getLogin(), user.getEmail(), user.getCreatedAt(), values);
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

  private String serializeProfile(List<UserProfileValue> values) {
    List<UserProfileValueResponse> snapshot = values.stream()
        .sorted(Comparator
            .comparing((UserProfileValue v) -> v.getField().getSortOrder(), Comparator.nullsLast(Integer::compareTo))
            .thenComparing(v -> v.getField().getId()))
        .map(this::toResponse)
        .collect(Collectors.toList());
    try {
      return objectMapper.writeValueAsString(snapshot);
    } catch (Exception ex) {
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to build profile snapshot");
    }
  }

  private List<UserProfileValueResponse> parseProfile(String json) {
    if (json == null || json.isBlank() || "{}".equals(json)) {
      return List.of();
    }
    try {
      return objectMapper.readValue(json, new TypeReference<List<UserProfileValueResponse>>() {});
    } catch (Exception ex) {
      return null;
    }
  }
}
