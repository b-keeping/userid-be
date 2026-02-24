package com.userid.dal.repo;

import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.dal.entity.DomainSocialProviderConfigEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DomainSocialProviderConfigRepository extends JpaRepository<DomainSocialProviderConfigEntity, Long> {
  Optional<DomainSocialProviderConfigEntity> findByDomainIdAndProvider(Long domainId, AuthServerSocialProviderEnum provider);

  void deleteByDomainId(Long domainId);
}
