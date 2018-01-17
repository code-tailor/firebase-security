package com.dw.fierbase.security.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class ServiceUser extends User {

  private static final long serialVersionUID = -2965284405561210973L;

  public ServiceUser(String username, String password,
      Collection<? extends GrantedAuthority> authorities) {
    super(username, password, authorities);
  }

}
