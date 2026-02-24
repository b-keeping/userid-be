package com.userid.dal.repo;

import com.userid.dal.entity.OwnerDomainEntity;
import com.userid.dal.entity.OwnerRoleEnum;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerDomainRepository extends JpaRepository<OwnerDomainEntity, Long> {
  List<OwnerDomainEntity> findByOwnerId(Long ownerId);

  boolean existsByOwnerIdAndDomainId(Long ownerId, Long domainId);

  List<OwnerDomainEntity> findByDomainId(Long domainId);

  void deleteByOwnerId(Long ownerId);

  void deleteByOwnerIdAndDomainId(Long ownerId, Long domainId);

  void deleteByDomainId(Long domainId);

  long countByDomainIdAndOwnerRole(Long domainId, OwnerRoleEnum role);

  long countByDomainIdAndOwnerRoleAndOwnerIdNot(
      Long domainId,
      OwnerRoleEnum role,
      Long ownerId
  );

  boolean existsByDomainId(Long domainId);

  boolean existsByDomainIdAndOwnerIdNot(Long domainId, Long ownerId);

}
