package com.userid.service;

import com.userid.api.user.UserProfileFilterRequestDTO;
import com.userid.api.user.UserProfileValueRequestDTO;
import com.userid.api.user.UserProfileValueResponseDTO;
import com.userid.api.user.UserRegistrationRequestDTO;
import com.userid.api.user.UserResponseDTO;
import com.userid.api.user.UserSearchRequestDTO;
import com.userid.api.user.UserUpdateRequestDTO;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.userid.dal.entity.DomainEntity;
import com.userid.dal.entity.FieldTypeEnum;
import com.userid.dal.entity.ProfileFieldEntity;
import com.userid.dal.entity.UserEntity;
import com.userid.dal.entity.UserProfileValueEntity;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.ProfileFieldRepository;
import com.userid.dal.repo.UserProfileValueRepository;
import com.userid.dal.repo.UserRepository;
import com.userid.dal.repo.UserSocialIdentityRepository;
import com.userid.api.client.EmailNormalizer;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
  private final DomainRepository domainRepository;
  private final ProfileFieldRepository profileFieldRepository;
  private final UserProfileValueRepository userProfileValueRepository;
  private final UserRepository userRepository;
  private final UserSocialIdentityRepository userSocialIdentityRepository;
  private final AccessService accessService;
  private final ObjectMapper objectMapper;
  private final PasswordEncoder passwordEncoder;
  private final EmailService emailService;
  private final UserOtpService userOtpService;

  @Transactional
  public UserResponseDTO register(Long serviceUserId, Long domainId, UserRegistrationRequestDTO request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    log.info("DB call domainRepository.findById domainId={} source=register", domainId);
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    return registerInternal(domain, request);
  }

  @Transactional
  public UserResponseDTO registerByDomain(Long domainId, UserRegistrationRequestDTO request) {
    log.info("DB call domainRepository.findById domainId={} source=registerByDomain", domainId);
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    return registerInternal(domain, request);
  }

  public UserResponseDTO get(Long serviceUserId, Long domainId, Long userId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    log.info("DB call userRepository.findByIdAndDomainId userId={} domainId={} source=get", userId, domainId);
    UserEntity user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    return toResponse(user);
  }

  public List<UserResponseDTO> search(Long serviceUserId, Long domainId, UserSearchRequestDTO request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    log.info("DB call domainRepository.existsById domainId={} source=search", domainId);
    if (!domainRepository.existsById(domainId)) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found");
    }
    List<UserProfileFilterRequestDTO> filters = request == null || request.filters() == null
        ? List.of()
        : request.filters();

    log.info("DB call profileFieldRepository.findByDomainId domainId={} source=search", domainId);
    Map<Long, ProfileFieldEntity> fieldById = toFieldMap(profileFieldRepository.findByDomainId(domainId));
    List<UserSearchFilterDTO> resolvedFilters = new ArrayList<>();

    for (UserProfileFilterRequestDTO filter : filters) {
      if (filter.fieldId() == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Filter field id is required");
      }
      ProfileFieldEntity field = fieldById.get(filter.fieldId());
      if (field == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown profile field id: " + filter.fieldId());
      }
      resolvedFilters.add(toSearchFilter(field, filter));
    }

    log.info(
        "DB call userRepository.searchByDomainAndFilters domainId={} filtersCount={} source=search",
        domainId,
        resolvedFilters.size());
    List<UserEntity> users = userRepository.searchByDomainAndFilters(domainId, resolvedFilters);
    return users.stream()
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public UserResponseDTO update(Long serviceUserId, Long domainId, Long userId, UserUpdateRequestDTO request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    log.info("DB call userRepository.findByIdAndDomainId userId={} domainId={} source=update", userId, domainId);
    UserEntity user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    return updateInternal(user, domainId, request, true);
  }

  public UserResponseDTO updateByDomain(Long domainId, Long userId, UserUpdateRequestDTO request) {
    log.info(
        "DB call userRepository.findByIdAndDomainId userId={} domainId={} source=updateByDomain",
        userId,
        domainId);
    UserEntity user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    return updateInternal(user, domainId, request, false);
  }

  @Transactional
  public void delete(Long serviceUserId, Long domainId, Long userId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    log.info("DB call userRepository.findByIdAndDomainId userId={} domainId={} source=delete", userId, domainId);
    UserEntity user = userRepository.findByIdAndDomainId(userId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    userOtpService.clearAllCodes(user);
    log.info("DB call userSocialIdentityRepository.deleteByUserId userId={} source=delete", user.getId());
    userSocialIdentityRepository.deleteByUserId(user.getId());
    log.info("DB call userProfileValueRepository.deleteByUserId userId={} source=delete", user.getId());
    userProfileValueRepository.deleteByUserId(user.getId());
    log.info("DB call userRepository.delete userId={} domainId={} source=delete", user.getId(), domainId);
    userRepository.delete(user);
  }

  @Transactional
  private UserResponseDTO registerInternal(DomainEntity domain, UserRegistrationRequestDTO request) {
    Long domainId = domain.getId();
    String email = EmailNormalizer.normalizeNullable(request.email());
    Optional<UserEntity> existingUser = findByDomainAndEmailOrPending(domainId, email);
    if (existingUser.isPresent()) {
      UserEntity existing = existingUser.get();
      if (existing.isActive()) {
        log.warn("DB duplicate user registration domainId={} emailPending={}", domainId, email);
        throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
      }
      log.info(
          "DB duplicate user registration resolved via pending user update domainId={} userId={} email={}",
          domainId,
          existing.getId(),
          email);
      return refreshUnconfirmedRegistration(existing, domain, request);
    }

    UserEntity user = UserEntity.builder()
        .domain(domain)
        .email(email)
        .emailPending(email)
        .passwordHash(passwordEncoder.encode(requirePassword(request.password())))
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .active(false)
        .build();

    applyProfileValues(user, domainId, request.values());
    log.info(
        "DB call userRepository.saveAndFlush domainId={} emailPending={} source=registerInternal",
        domainId,
        user.getEmailPending());
    UserEntity saved;
    try {
      saved = userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      if (isDuplicateUserEmailViolation(ex)) {
        log.warn("DB duplicate user registration domainId={} emailPending={}", domainId, user.getEmailPending());
        throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
      }
      throw ex;
    }
    log.info(
        "DB result userRepository.saveAndFlush userId={} domainId={} email={} emailPending={} source=registerInternal",
        saved.getId(),
        domainId,
        saved.getEmail(),
        saved.getEmailPending());
    String otpCode = userOtpService.createVerificationCode(saved);
    emailService.sendOtpEmail(domain, resolveVerificationEmail(saved), otpCode);
    return toResponse(saved);
  }

  private UserResponseDTO refreshUnconfirmedRegistration(UserEntity user, DomainEntity domain, UserRegistrationRequestDTO request) {
    Long domainId = domain.getId();
    String email = EmailNormalizer.normalizeNullable(request.email());
    String currentEmail = resolveDisplayedEmail(user);
    boolean emailChanged = currentEmail == null || !currentEmail.equals(email);
    user.setEmail(email);
    user.setEmailPending(email);
    if (emailChanged) {
      user.setEmailVerifiedAt(null);
    }
    user.setActive(false);
    user.setPasswordHash(passwordEncoder.encode(requirePassword(request.password())));
    applyProfileValues(user, domainId, request.values());

    log.info(
        "DB call userRepository.saveAndFlush userId={} domainId={} email={} emailPending={} source=refreshUnconfirmedRegistration",
        user.getId(),
        domainId,
        user.getEmail(),
        user.getEmailPending());
    UserEntity saved;
    try {
      saved = userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      if (isDuplicateUserEmailViolation(ex)) {
        log.warn(
            "DB duplicate user registration refresh userId={} domainId={} email={} emailPending={}",
            user.getId(),
            domainId,
            user.getEmail(),
            user.getEmailPending());
        throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
      }
      throw ex;
    }
    if (saved.getEmailVerifiedAt() == null) {
      String otpCode = userOtpService.reuseVerificationCode(saved);
      emailService.sendOtpEmail(domain, resolveVerificationEmail(saved), otpCode);
    }
    return toResponse(saved);
  }

  private Optional<UserEntity> findByDomainAndEmailOrPending(Long domainId, String email) {
    return userRepository.findByDomainIdAndEmail(domainId, email)
        .or(() -> userRepository.findByDomainIdAndEmailPending(domainId, email));
  }

  private UserResponseDTO updateInternal(UserEntity user, Long domainId, UserUpdateRequestDTO request, boolean allowConfirmed) {
    if (!allowConfirmed && request.confirmed() != null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Confirmed flag is not allowed");
    }

    boolean emailChanged = false;
    if (request.password() != null && !request.password().isBlank()) {
      user.setPasswordHash(passwordEncoder.encode(request.password()));
    }
    if (request.email() != null && !request.email().isBlank()) {
      String requestedEmail = EmailNormalizer.normalizeNullable(request.email());
      String currentEmail = resolveDisplayedEmail(user);
      if (currentEmail == null || !requestedEmail.equals(currentEmail)) {
        emailChanged = true;
      }
      user.setEmailPending(requestedEmail);
    }

    if (allowConfirmed && request.confirmed() != null) {
      if (request.confirmed()) {
        user.setEmail(requireValue(user.getEmailPending(), "emailPending"));
        user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
      } else {
        user.setEmailVerifiedAt(null);
        user.setActive(false);
        userOtpService.clearVerificationCode(user);
      }
    }

    if (request.values() != null) {
      applyProfileValues(user, domainId, request.values());
    }

    boolean sendVerificationOtp = emailChanged && (!allowConfirmed || request.confirmed() == null || !request.confirmed());
    if (sendVerificationOtp) {
      user.setEmailVerifiedAt(null);
    }

    log.info(
        "DB call userRepository.saveAndFlush userId={} domainId={} email={} emailPending={} source=updateInternal",
        user.getId(),
        domainId,
        user.getEmail(),
        user.getEmailPending());
    UserEntity saved;
    try {
      saved = userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      if (isDuplicateUserEmailViolation(ex)) {
        log.warn(
            "DB duplicate user update userId={} domainId={} email={} emailPending={}",
            user.getId(),
            domainId,
            user.getEmail(),
            user.getEmailPending());
        throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
      }
      throw ex;
    }
    log.info(
        "DB result userRepository.saveAndFlush userId={} domainId={} email={} emailPending={} source=updateInternal",
        saved.getId(),
        domainId,
        saved.getEmail(),
        saved.getEmailPending());
    if (sendVerificationOtp) {
      String otpCode = userOtpService.createVerificationCode(saved);
      emailService.sendOtpEmail(user.getDomain(), resolveVerificationEmail(saved), otpCode);
    }
    return toResponse(saved);
  }

  private Map<Long, ProfileFieldEntity> toFieldMap(List<ProfileFieldEntity> fields) {
    Map<Long, ProfileFieldEntity> fieldById = new HashMap<>();
    for (ProfileFieldEntity field : fields) {
      fieldById.put(field.getId(), field);
    }
    return fieldById;
  }

  void applyProfileValues(UserEntity user, Long domainId, List<UserProfileValueRequestDTO> requests) {
    log.info("DB call profileFieldRepository.findByDomainId domainId={} source=applyProfileValues", domainId);
    List<ProfileFieldEntity> fields = profileFieldRepository.findByDomainId(domainId);
    Map<Long, ProfileFieldEntity> fieldById = toFieldMap(fields);
    List<UserProfileValueRequestDTO> valueRequests = requests == null ? List.of() : requests;

    Set<UserProfileValueEntity> userValues = user.getValues();
    List<UserProfileValueEntity> existingValues = user.getId() == null
        ? List.of()
        : loadUserValuesForUpdate(user.getId());
    for (UserProfileValueEntity existing : existingValues) {
      userValues.add(existing);
    }

    Map<Long, UserProfileValueEntity> valueByFieldId = new HashMap<>();
    for (UserProfileValueEntity existing : userValues) {
      if (existing.getField() != null && existing.getField().getId() != null) {
        valueByFieldId.put(existing.getField().getId(), existing);
      }
    }

    Set<Long> providedFieldIds = new HashSet<>();
    List<Long> unknownFieldIds = new ArrayList<>();

    for (UserProfileValueRequestDTO rawRequest : valueRequests) {
      UserProfileValueRequestDTO valueRequest = stripDisplayName(rawRequest);
      Long fieldId = valueRequest.fieldId();
      if (fieldId == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Profile field id is required");
      }
      ProfileFieldEntity field = fieldById.get(fieldId);
      if (field == null) {
        unknownFieldIds.add(fieldId);
        continue;
      }
      if (!providedFieldIds.add(fieldId)) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Duplicate profile field id: " + fieldId);
      }

      UserProfileValueEntity value = valueByFieldId.get(fieldId);
      if (value == null) {
        value = new UserProfileValueEntity();
        value.setUser(user);
        value.setField(field);
        userValues.add(value);
        valueByFieldId.put(fieldId, value);
      }
      applyValue(value, field.getType(), valueRequest);
    }

    if (!unknownFieldIds.isEmpty()) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST,
          "Unknown profile field id(s): " + unknownFieldIds.stream().map(String::valueOf).collect(Collectors.joining(", "))
      );
    }

    boolean requireAllMandatory = user.getId() == null;
    List<String> missingMandatory = fields.stream()
        .filter(ProfileFieldEntity::isMandatory)
        .filter(field -> requireAllMandatory
            ? !providedFieldIds.contains(field.getId())
            : !providedFieldIds.contains(field.getId()) && !valueByFieldId.containsKey(field.getId()))
        .map(ProfileFieldEntity::getName)
        .toList();

    if (!missingMandatory.isEmpty()) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST,
          "Missing mandatory fields: " + String.join(", ", missingMandatory)
      );
    }

    user.setProfileJsonb(serializeProfile(new ArrayList<>(valueByFieldId.values())));
  }

  private List<UserProfileValueEntity> loadUserValuesForUpdate(Long userId) {
    log.info("DB call userProfileValueRepository.findByUserId userId={} source=applyProfileValues", userId);
    return userProfileValueRepository.findByUserId(userId);
  }

  private boolean isDuplicateUserEmailViolation(DataIntegrityViolationException ex) {
    String message = ex.getMessage();
    if (message == null) {
      return false;
    }
    String normalized = message.toLowerCase();
    return normalized.contains("uk_users_domain_email")
        || normalized.contains("uk_users_domain_email_pending")
        || normalized.contains("duplicate key")
        || normalized.contains("unique index or primary key violation");
  }

  private void applyValue(UserProfileValueEntity value, FieldTypeEnum type, UserProfileValueRequestDTO request) {
    switch (type) {
      case STRING -> {
        requireValue(request.stringValue(), "stringValue");
        value.setValueString(request.stringValue());
      }
      case NUMERIC -> {
        String numeric = requireDigits(request.numericValue(), "numericValue");
        value.setValueString(numeric);
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

  private static UserProfileValueRequestDTO stripDisplayName(UserProfileValueRequestDTO request) {
    // "name" is accepted in incoming JSON for UI/docs convenience and ignored by backend logic.
    return new UserProfileValueRequestDTO(
        request.fieldId(),
        null,
        request.stringValue(),
        request.numericValue(),
        request.booleanValue(),
        request.integerValue(),
        request.decimalValue(),
        request.dateValue(),
        request.timeValue(),
        request.timestampValue());
  }

  private UserSearchFilterDTO toSearchFilter(ProfileFieldEntity field, UserProfileFilterRequestDTO request) {
    return switch (field.getType()) {
      case STRING -> new UserSearchFilterDTO(field.getId(), field.getType(),
          requireValue(request.stringValue(), "stringValue"), null, null, null, null, null, null);
      case NUMERIC -> new UserSearchFilterDTO(field.getId(), field.getType(),
          requireDigits(request.numericValue(), "numericValue"), null, null, null, null, null, null);
      case BOOLEAN -> new UserSearchFilterDTO(field.getId(), field.getType(),
          null, requireValue(request.booleanValue(), "booleanValue"), null, null, null, null, null);
      case INTEGER -> new UserSearchFilterDTO(field.getId(), field.getType(),
          null, null, requireValue(request.integerValue(), "integerValue"), null, null, null, null);
      case DECIMAL -> new UserSearchFilterDTO(field.getId(), field.getType(),
          null, null, null, requireValue(request.decimalValue(), "decimalValue"), null, null, null);
      case DATE -> new UserSearchFilterDTO(field.getId(), field.getType(),
          null, null, null, null, requireValue(request.dateValue(), "dateValue"), null, null);
      case TIME -> new UserSearchFilterDTO(field.getId(), field.getType(),
          null, null, null, null, null, requireValue(request.timeValue(), "timeValue"), null);
      case TIMESTAMP -> new UserSearchFilterDTO(field.getId(), field.getType(),
          null, null, null, null, null, null, requireValue(request.timestampValue(), "timestampValue"));
    };
  }

  UserResponseDTO toResponse(UserEntity user) {
    List<UserProfileValueResponseDTO> values = parseProfile(user.getProfileJsonb());
    if (values == null) {
      values = user.getValues().stream()
          .sorted(Comparator
              .comparing((UserProfileValueEntity v) -> v.getField().getSortOrder(), Comparator.nullsLast(Integer::compareTo))
              .thenComparing(v -> v.getField().getId()))
          .map(this::toResponse)
          .collect(Collectors.toList());
    }

    boolean confirmed = user.getEmailVerifiedAt() != null;
    return new UserResponseDTO(
        user.getId(),
        resolveDisplayedEmail(user),
        confirmed,
        user.isActive(),
        user.getCreatedAt(),
        values);
  }

  private String resolveDisplayedEmail(UserEntity user) {
    if (user.getEmail() != null && !user.getEmail().isBlank()) {
      return user.getEmail();
    }
    return user.getEmailPending();
  }

  private String resolveVerificationEmail(UserEntity user) {
    String email = resolveDisplayedEmail(user);
    if (email == null || email.isBlank()) {
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "User email is not set");
    }
    return email;
  }

  private UserProfileValueResponseDTO toResponse(UserProfileValueEntity value) {
    ProfileFieldEntity field = value.getField();
    String stringValue = field.getType() == FieldTypeEnum.NUMERIC ? null : value.getValueString();
    String numericValue = field.getType() == FieldTypeEnum.NUMERIC ? value.getValueString() : null;
    return new UserProfileValueResponseDTO(
        field.getId(),
        field.getName(),
        field.getType(),
        field.isMandatory(),
        stringValue,
        numericValue,
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

  private static String requireDigits(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing value for " + name);
    }
    if (!value.chars().allMatch(Character::isDigit)) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid numeric value for " + name);
    }
    return value;
  }

  private static String requirePassword(String password) {
    if (password == null || password.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
    }
    return password;
  }

  private JsonNode serializeProfile(List<UserProfileValueEntity> values) {
    List<UserProfileValueResponseDTO> snapshot = values.stream()
        .sorted(Comparator
            .comparing((UserProfileValueEntity v) -> v.getField().getSortOrder(), Comparator.nullsLast(Integer::compareTo))
            .thenComparing(v -> v.getField().getId()))
        .map(this::toResponse)
        .collect(Collectors.toList());
    return objectMapper.valueToTree(snapshot);
  }

  private List<UserProfileValueResponseDTO> parseProfile(JsonNode json) {
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
      return objectMapper.convertValue(json, new TypeReference<List<UserProfileValueResponseDTO>>() {});
    } catch (Exception ex) {
      return null;
    }
  }
}
