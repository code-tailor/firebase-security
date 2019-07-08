package com.dw.fierbase.security.filter;

import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.core.ApiFuture;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FirebaseAuthenticationFilter implements Filter {

  private static final Logger logger = LoggerFactory.getLogger(FirebaseAuthenticationFilter.class);
  private static final String TOKEN_HEADER = "X-Firebase-Auth";
  private static final String CACHE_FIREBASE_ID_TOKEN = "firebaseIdToken";

  private CacheManager cacheManager;

  public FirebaseAuthenticationFilter(CacheManager cacheManager) {
    this.cacheManager = cacheManager;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    logger.debug("init():: FirebaseAuthenticationFilter initialization.");
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String authToken = httpRequest.getHeader(TOKEN_HEADER);

    if (StringUtils.isBlank(authToken)) {
      logger.debug("Missing authToken.");
      chain.doFilter(request, response);
      return;
    }

    String obfuscatedToken = StringUtils.abbreviateMiddle(authToken, "...", 20);
    HttpServletResponse httpResponse = (HttpServletResponse) response;

    try {
      Authentication authentication = getAndValidateAuthentication(authToken);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      logger.debug("doFilter():: Successfully authenticated. authToken={}", obfuscatedToken);
    } catch (Exception ex) {
      String userDetail = getUserDetails(authToken);

      // check root cuase is FirebaseAuthException
      Throwable exception = ExceptionUtils.getRootCause(ex);
      if (exception instanceof FirebaseAuthException) {
        FirebaseAuthException firebaseAuthEx = (FirebaseAuthException) exception;
        String errorCode = firebaseAuthEx.getErrorCode();

        // Check error code is 'ERROR_INVALID_CREDENTIAL'
        if (StringUtils.equals(errorCode, "ERROR_INVALID_CREDENTIAL")) {
          httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          // Check if firebase token is expired
          if (StringUtils.startsWith(exception.getMessage(),
              "Firebase ID token has expired or is not valid anymore")) {
            logger.warn("Firebase ID token has expired or is not valid anymore. token={}; "
                + "userDetail={}.", obfuscatedToken, userDetail,ex);
            return;
          }

          // The supplied auth credential is malformed.
          logger.error("Authentication error for token={}; userDetail={}.", obfuscatedToken,
              userDetail, ex);
          return;
        }
      }

      httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      logger.debug("Invalid authentication. authToken={}; userDetail={}.", obfuscatedToken,
          userDetail, ex);
      return;
    }

    chain.doFilter(request, response);
  }

  private Authentication getAndValidateAuthentication(String authToken) throws Exception {
    Authentication authentication = null;

    Cache cache = cacheManager.getCache(CACHE_FIREBASE_ID_TOKEN);
    if (cache.get(authToken) != null) {
      authentication = cache.get(authToken, Authentication.class);
      return authentication;
    }

    FirebaseToken firebaseToken = authenticateFirebaseToken(authToken);
    authentication =
        new UsernamePasswordAuthenticationToken(firebaseToken, authToken, new ArrayList<>());
    cache.put(authToken, authentication);
    return authentication;
  }

  private FirebaseToken authenticateFirebaseToken(String authToken) throws Exception {
    ApiFuture<FirebaseToken> app = FirebaseAuth.getInstance().verifyIdTokenAsync(authToken);

    try {
      return app.get();
    } catch (InterruptedException | ExecutionException ex) {
      throw ex;
    }
  }

  private String getUserDetails(String authToken) {
    try {
      JsonWebSignature jws = JsonWebSignature
          .parser(FirebaseApp.getInstance().getOptions().getJsonFactory()).parse(authToken);
      return jws.getPayload() == null ? null : jws.getPayload().toString();
    } catch (Exception ex) {
      logger.debug("Fail to extract token={}", authToken, ex);
    }

    return null;
  }

  @Override
  public void destroy() {
    logger.debug("destroy():: invoke");
  }
}
