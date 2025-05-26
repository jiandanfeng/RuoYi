package com.ruoyi.framework.security.listener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicInteger;

@Component
public class AuthenticationEventListeners {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationEventListeners.class);

    // Define the cache name, same as used in Shiro's configuration for login records
    public static final String LOGIN_RECORD_CACHE_NAME = "loginRecordCache";

    @Autowired
    private CacheManager cacheManager;

    @Value("${user.password.maxRetryCount:5}") // Default to 5 if not set in properties
    private int maxRetryCount;

    @EventListener
    public void handleAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        String username = event.getAuthentication().getName();
        if (username == null) {
            return; // Should not happen for UsernamePasswordAuthenticationToken
        }

        Cache cache = cacheManager.getCache(LOGIN_RECORD_CACHE_NAME);
        if (cache == null) {
            log.error("Cache '{}' not found. Login attempt limiting will not work.", LOGIN_RECORD_CACHE_NAME);
            return;
        }

        AtomicInteger retryCount = cache.get(username, AtomicInteger.class);
        if (retryCount == null) {
            retryCount = new AtomicInteger(0);
        }
        
        int currentAttempts = retryCount.incrementAndGet();
        cache.put(username, retryCount);
        log.info("User {} failed login attempt. Current attempts: {}", username, currentAttempts);

        if (currentAttempts >= maxRetryCount) {
            log.warn("User {} has been locked due to {} failed login attempts.", username, maxRetryCount);
            // The actual locking by throwing LockedException will be done in CustomAuthenticationProvider
            // This listener just records and logs.
        }
    }

    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        if (username == null) {
            return;
        }

        Cache cache = cacheManager.getCache(LOGIN_RECORD_CACHE_NAME);
        if (cache == null) {
            // Logged in handleAuthenticationFailure, no need to repeat unless for specific success context
            return;
        }

        if (cache.get(username) != null) {
            cache.evict(username);
            log.info("User {} successfully logged in. Cleared login attempt records.", username);
        }
    }
}
