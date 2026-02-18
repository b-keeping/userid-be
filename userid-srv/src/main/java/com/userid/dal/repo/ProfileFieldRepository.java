package com.userid.dal.repo;

import com.userid.dal.entity.ProfileField;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProfileFieldRepository extends JpaRepository<ProfileField, Long> {
  boolean existsByDomainId(Long domainId);

  List<ProfileField> findByDomainIdOrderBySortOrderAscIdAsc(Long domainId);

  Optional<ProfileField> findByDomainIdAndName(Long domainId, String name);

  List<ProfileField> findByDomainId(Long domainId);

  Optional<ProfileField> findByIdAndDomainId(Long id, Long domainId);
}
