package com.userid.dal.entity;

import com.userid.api.client.AuthServerSocialProvider;
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
import com.userid.util.EmailNormalizer;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
    name = "user_social_identities",
    uniqueConstraints = {
      @UniqueConstraint(
          name = "uk_user_social_identity_domain_provider_subject",
          columnNames = {"domain_id", "provider", "provider_subject"}
      )
    },
    indexes = {
      @Index(name = "idx_user_social_identity_user", columnList = "user_id"),
      @Index(name = "idx_user_social_identity_domain", columnList = "domain_id")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSocialIdentity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(optional = false)
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  @ManyToOne(optional = false)
  @JoinColumn(name = "domain_id", nullable = false)
  private Domain domain;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 32)
  private AuthServerSocialProvider provider;

  @Column(name = "provider_subject", nullable = false, length = 255)
  private String providerSubject;

  @Column(name = "provider_email", length = 255)
  private String providerEmail;

  @Column(name = "provider_email_verified")
  private Boolean providerEmailVerified;

  @Column(name = "created_at", nullable = false)
  private OffsetDateTime createdAt;

  @PrePersist
  void onCreate() {
    createdAt = OffsetDateTime.now(ZoneOffset.UTC);
    providerEmail = EmailNormalizer.normalizeNullable(providerEmail);
  }

  @PreUpdate
  void onUpdate() {
    providerEmail = EmailNormalizer.normalizeNullable(providerEmail);
  }
}
