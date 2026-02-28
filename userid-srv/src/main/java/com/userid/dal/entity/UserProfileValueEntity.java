package com.userid.dal.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
    name = "user_profile_value",
    uniqueConstraints = {
      @UniqueConstraint(name = "uk_user_profile_values_user_field", columnNames = {"user_id", "field_id"})
    },
    indexes = {
      @Index(name = "idx_user_profile_values_user", columnList = "user_id"),
      @Index(name = "idx_user_profile_values_field_string", columnList = "field_id,value_string"),
      @Index(name = "idx_user_profile_values_field_boolean", columnList = "field_id,value_boolean"),
      @Index(name = "idx_user_profile_values_field_integer", columnList = "field_id,value_integer"),
      @Index(name = "idx_user_profile_values_field_decimal", columnList = "field_id,value_decimal"),
      @Index(name = "idx_user_profile_values_field_date", columnList = "field_id,value_date"),
      @Index(name = "idx_user_profile_values_field_time", columnList = "field_id,value_time"),
      @Index(name = "idx_user_profile_values_field_timestamp", columnList = "field_id,value_timestamp")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserProfileValueEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", nullable = false)
  private UserEntity user;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "field_id", nullable = false)
  private ProfileFieldEntity field;

  @Column(name = "value_string", length = 1024)
  private String valueString;

  @Column(name = "value_boolean")
  private Boolean valueBoolean;

  @Column(name = "value_integer")
  private Long valueInteger;

  @Column(name = "value_decimal", precision = 20, scale = 6)
  private BigDecimal valueDecimal;

  @Column(name = "value_date")
  private LocalDate valueDate;

  @Column(name = "value_time")
  private LocalTime valueTime;

  @Column(name = "value_timestamp")
  private OffsetDateTime valueTimestamp;
}
