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
    name = "owner_social_identity",
    uniqueConstraints = {
      @UniqueConstraint(
          name = "uk_owner_social_identity_provider_subject",
          columnNames = {"provider", "provider_subject"}
      )
    },
    indexes = {
      @Index(name = "idx_owner_social_identity_owner", columnList = "owner_id")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OwnerSocialIdentityEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(optional = false)
  @JoinColumn(name = "owner_id", nullable = false)
  private OwnerEntity owner;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 32)
  private AuthServerSocialProviderEnum provider;

  @Column(name = "provider_subject", nullable = false, length = 255)
  private String providerSubject;

  @Column(name = "provider_email", length = 255)
  private String providerEmail;

  @Column(name = "provider_email_verified")
  private Boolean providerEmailVerified;

  @Column(name = "created_at", nullable = false)
  private OffsetDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private OffsetDateTime updatedAt;

  @PrePersist
  void onCreate() {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    createdAt = now;
    updatedAt = now;
  }

  @PreUpdate
  void onUpdate() {
    updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
  }
}
