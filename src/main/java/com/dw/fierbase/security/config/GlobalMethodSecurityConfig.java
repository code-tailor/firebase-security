package com.dw.fierbase.security.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@ConditionalOnMissingBean({GlobalMethodSecurityConfiguration.class})
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class GlobalMethodSecurityConfig {

  private static final Logger logger = LoggerFactory.getLogger(GlobalMethodSecurityConfig.class);

  public GlobalMethodSecurityConfig() {
    logger.info("GlobalMethodSecurityConfig :: Initialized.");
  }

}
