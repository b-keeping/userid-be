package com.userid.dal.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.HashSet;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "domains")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Domain {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 255)
  private String name;

  @Column(name = "dns_status", length = 32)
  private String dnsStatus;

  @Column(name = "dns_error", length = 1024)
  private String dnsError;

  @Column(name = "verify", length = 1024)
  private String verify;

  @Column(name = "verify_host", length = 512)
  private String verifyHost;

  @Column(name = "verify_type", length = 16)
  private String verifyType;

  @Column(name = "verify_stt")
  private Boolean verifyStt;

  @Column(name = "spf", length = 2048)
  private String spf;

  @Column(name = "spf_host", length = 512)
  private String spfHost;

  @Column(name = "spf_type", length = 16)
  private String spfType;

  @Column(name = "spf_stt")
  private Boolean spfStt;

  @Column(name = "dkim", length = 4096)
  private String dkim;

  @Column(name = "dkim_host", length = 512)
  private String dkimHost;

  @Column(name = "dkim_type", length = 16)
  private String dkimType;

  @Column(name = "dkim_stt")
  private Boolean dkimStt;

  @Column(name = "mx", length = 1024)
  private String mx;

  @Column(name = "mx_host", length = 512)
  private String mxHost;

  @Column(name = "mx_type", length = 16)
  private String mxType;

  @Column(name = "mx_priority")
  private Integer mxPriority;

  @Column(name = "mx_optional")
  private Boolean mxOptional;

  @Column(name = "mx_stt")
  private Boolean mxStt;

  @Column(name = "return_path", length = 1024)
  private String returnPath;

  @Column(name = "return_path_host", length = 512)
  private String returnPathHost;

  @Column(name = "return_path_type", length = 16)
  private String returnPathType;

  @Column(name = "return_path_stt")
  private Boolean returnPathStt;

  @Builder.Default
  @OneToMany(mappedBy = "domain", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<ProfileField> profileFields = new HashSet<>();

  @Builder.Default
  @OneToMany(mappedBy = "domain", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<User> users = new HashSet<>();
}
