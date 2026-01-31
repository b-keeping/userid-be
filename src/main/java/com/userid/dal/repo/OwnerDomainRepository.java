package com.userid.dal.repo;

import com.userid.dal.entity.OwnerDomain;
import com.userid.dal.entity.OwnerRole;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerDomainRepository extends JpaRepository<OwnerDomain, Long> {
  List<OwnerDomain> findByOwnerId(Long ownerId);

  boolean existsByOwnerIdAndDomainId(Long ownerId, Long domainId);

  List<OwnerDomain> findByDomainId(Long domainId);

  void deleteByOwnerId(Long ownerId);

  void deleteByOwnerIdAndDomainId(Long ownerId, Long domainId);

  void deleteByDomainId(Long domainId);

  long countByDomainIdAndOwnerRole(Long domainId, OwnerRole role);

  long countByDomainIdAndOwnerRoleAndOwnerIdNot(
      Long domainId,
      OwnerRole role,
      Long ownerId
  );

  boolean existsByDomainId(Long domainId);

  boolean existsByDomainIdAndOwnerIdNot(Long domainId, Long ownerId);

}
