package com.userid.dal.repo;

import com.userid.dal.entity.ProfileFieldEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProfileFieldRepository extends JpaRepository<ProfileFieldEntity, Long> {
  boolean existsByDomainId(Long domainId);

  List<ProfileFieldEntity> findByDomainIdOrderBySortOrderAscIdAsc(Long domainId);

  Optional<ProfileFieldEntity> findByDomainIdAndName(Long domainId, String name);

  List<ProfileFieldEntity> findByDomainId(Long domainId);

  Optional<ProfileFieldEntity> findByIdAndDomainId(Long id, Long domainId);
}
