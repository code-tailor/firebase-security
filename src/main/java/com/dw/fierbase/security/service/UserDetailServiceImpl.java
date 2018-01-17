package com.dw.fierbase.security.service;

import com.dw.fierbase.security.dto.ServiceUser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class UserDetailServiceImpl implements UserDetailsService {

  private static final Logger logger = LoggerFactory.getLogger(UserDetailServiceImpl.class);

  @Value("${client.service.preSharePassword}")
  private String preSharePassword;

  @Value("${client.service.role:TRUSTED_SERVICE}")
  private String role;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Override
  public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
    logger.debug("loadUserByUsername() :: user:{}, presharedPassword: {}", userId,
        preSharePassword);

    List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
    authorities.add(new SimpleGrantedAuthority(getAuthority(role)));

    ServiceUser user =
        new ServiceUser(userId, passwordEncoder().encode(preSharePassword), authorities);
    return user;
  }

  public String getAuthority(String name) {
    return "ROLE_" + name;
  }

}

