package com.userid.dal.repo;

import com.userid.api.client.AuthServerSocialProvider;
import com.userid.dal.entity.DomainSocialProviderConfig;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DomainSocialProviderConfigRepository extends JpaRepository<DomainSocialProviderConfig, Long> {
  Optional<DomainSocialProviderConfig> findByDomainIdAndProvider(Long domainId, AuthServerSocialProvider provider);

  void deleteByDomainId(Long domainId);
}
