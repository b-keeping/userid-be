package com.userid.dal.repo;

import com.userid.api.client.AuthServerSocialProvider;
import com.userid.dal.entity.OwnerSocialIdentity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerSocialIdentityRepository extends JpaRepository<OwnerSocialIdentity, Long> {
  Optional<OwnerSocialIdentity> findByProviderAndProviderSubject(
      AuthServerSocialProvider provider,
      String providerSubject
  );
}
