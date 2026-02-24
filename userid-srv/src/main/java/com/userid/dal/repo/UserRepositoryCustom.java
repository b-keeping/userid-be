package com.userid.dal.repo;

import com.userid.dal.entity.UserEntity;
import com.userid.service.UserSearchFilterDTO;
import java.util.List;

public interface UserRepositoryCustom {
  List<UserEntity> searchByDomainAndFilters(Long domainId, List<UserSearchFilterDTO> filters);
}
