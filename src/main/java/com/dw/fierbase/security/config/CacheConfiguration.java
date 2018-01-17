package com.dw.fierbase.security.config;

import com.google.common.cache.CacheBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@EnableCaching
@Configuration
public class CacheConfiguration {

  private static final Logger logger = LoggerFactory.getLogger(CacheConfiguration.class);

  /**
   * Create instance of CacheManger for cache.<br/>
   * Cache evict base of it policy which is evict key when it is unused in 60 min.
   * 
   * @return instance of {@link CacheManager}
   */
  @Bean("securityCacheManager")
  public CacheManager securityCacheManager() {
    logger.debug("cacheManager():: creating bean of cache manager.");
    ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager() {

      @Override
      protected Cache createConcurrentMapCache(final String name) {
        return new ConcurrentMapCache(name,
            CacheBuilder.newBuilder().expireAfterAccess(60, TimeUnit.MINUTES).build().asMap(),
            false);
      }
    };

    return cacheManager;
  }
}
