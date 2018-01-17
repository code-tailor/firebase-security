package com.dw.fierbase.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan
public class FirebaseSecurityAutoConfiguration {

  private static Logger logger = LoggerFactory.getLogger(FirebaseSecurityAutoConfiguration.class);

  public static void main(String[] args) {
    logger.debug("FirebaseSecurityAutoConfiguration() :: Initialized.");
  }
}
