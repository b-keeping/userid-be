package com.userid.dal.entity;

import com.userid.api.client.AuthServerSocialProviderEnum;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
    name = "domain_social_provider_configs",
    uniqueConstraints = {
      @UniqueConstraint(
          name = "uk_domain_social_provider_config_domain_provider",
          columnNames = {"domain_id", "provider"}
      )
    },
    indexes = {
      @Index(name = "idx_domain_social_provider_config_domain", columnList = "domain_id")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DomainSocialProviderConfigEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(optional = false)
  @JoinColumn(name = "domain_id", nullable = false)
  private DomainEntity domain;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 32)
  private AuthServerSocialProviderEnum provider;

  @Column(nullable = false)
  private Boolean enabled;

  @Column(name = "client_id", length = 512)
  private String clientId;

  @Column(name = "client_secret", length = 2048)
  private String clientSecret;

  @Column(name = "callback_uri", length = 2048)
  private String callbackUri;

  @Column(name = "created_at", nullable = false)
  private OffsetDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private OffsetDateTime updatedAt;

  @PrePersist
  void onCreate() {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    if (enabled == null) {
      enabled = false;
    }
    createdAt = now;
    updatedAt = now;
  }

  @PreUpdate
  void onUpdate() {
    updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
  }
}
