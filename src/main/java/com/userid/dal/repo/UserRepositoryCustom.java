package com.userid.dal.repo;

import com.userid.dal.entity.User;
import com.userid.service.UserSearchFilter;
import java.util.List;

public interface UserRepositoryCustom {
  List<User> searchByDomainAndFilters(Long domainId, List<UserSearchFilter> filters);
}
