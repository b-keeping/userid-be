package com.userid.dal.repo;

import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.dal.entity.UserSocialIdentityEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserSocialIdentityRepository extends JpaRepository<UserSocialIdentityEntity, Long> {
  Optional<UserSocialIdentityEntity> findByDomainIdAndProviderAndProviderSubject(
      Long domainId,
      AuthServerSocialProviderEnum provider,
      String providerSubject
  );

  void deleteByDomainId(Long domainId);

  void deleteByUserId(Long userId);
}
