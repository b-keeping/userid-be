package com.userid.dal.repo;

import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.dal.entity.OwnerSocialIdentityEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerSocialIdentityRepository extends JpaRepository<OwnerSocialIdentityEntity, Long> {
  Optional<OwnerSocialIdentityEntity> findByProviderAndProviderSubject(
      AuthServerSocialProviderEnum provider,
      String providerSubject
  );

  long deleteByOwnerId(Long ownerId);
}
