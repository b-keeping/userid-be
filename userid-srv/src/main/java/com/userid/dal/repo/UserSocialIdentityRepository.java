package com.userid.dal.repo;

import com.userid.api.client.AuthServerSocialProvider;
import com.userid.dal.entity.UserSocialIdentity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserSocialIdentityRepository extends JpaRepository<UserSocialIdentity, Long> {
  Optional<UserSocialIdentity> findByDomainIdAndProviderAndProviderSubject(
      Long domainId,
      AuthServerSocialProvider provider,
      String providerSubject
  );

  void deleteByDomainId(Long domainId);

  void deleteByUserId(Long userId);
}
