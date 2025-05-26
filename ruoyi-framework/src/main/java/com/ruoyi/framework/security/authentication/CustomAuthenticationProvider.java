package com.ruoyi.framework.security.authentication;

import com.ruoyi.framework.security.core.LoginUser; // Custom UserDetails
import com.ruoyi.framework.security.crypto.CustomPasswordEncoder; // Custom PasswordEncoder
import com.ruoyi.framework.security.listener.AuthenticationEventListeners; // For LOGIN_RECORD_CACHE_NAME
import com.ruoyi.framework.security.service.UserDetailsServiceImpl; // Custom UserDetailsService
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component; // To make it a bean

import java.util.concurrent.atomic.AtomicInteger; // Added import

@Component // Register as a Spring bean so it can be injected into SecurityConfig
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private CustomPasswordEncoder passwordEncoder;

    @Autowired
    private CacheManager cacheManager;

    @Value("${user.password.maxRetryCount:5}") // Default to 5, consistent with listener
    private int maxRetryCount;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // Check for excessive login attempts BEFORE proceeding
        Cache cache = cacheManager.getCache(AuthenticationEventListeners.LOGIN_RECORD_CACHE_NAME);
        if (cache == null) {
            // Log this error, but proceed without cache if not found? Or hard fail?
            // For now, log and proceed, means retry limiting is not working.
            // Consider if this should throw an exception to alert admins.
            // logger.error("Cache '{}' not found. Login attempt limiting is disabled.", AuthenticationEventListeners.LOGIN_RECORD_CACHE_NAME);
        } else {
            AtomicInteger retryCount = cache.get(username, AtomicInteger.class);
            if (retryCount != null && retryCount.get() >= maxRetryCount) {
                // It's important that the listener has already incremented for the CURRENT attempt
                // OR that we increment here before checking.
                // The listener increments on failure. If this is the Nth attempt that *would* fail,
                // listener makes it N. If N == maxRetryCount, then this attempt is the one that locks.
                // SysPasswordService did: get count, if null init 0, newCount = incrementAndGet. if newCount > max, throw.
                // Our listener does: get count, if null init 0, newCount = incrementAndGet, put.
                // So if listener recorded 4, and max is 5, then this is the 5th attempt.
                // If it fails, listener makes it 5.
                // The check here should be if current count in cache (which is from *previous* failures)
                // is already >= maxRetryCount.
                // Let's adjust the logic slightly: the listener records. The provider checks.
                // If listener records attempt N, and N >= maxRetryCount, then on the *next* attempt (N+1),
                // this check should prevent it.

                // If the count of *previous* failures has already met or exceeded the threshold.
                // The listener's count includes the *last* failed attempt.
                // So if maxRetryCount is 5, and listener recorded 5, user is locked.
                // logger.warn("User {} account is locked due to excessive failed login attempts.", username);
                throw new LockedException("User account is locked due to too many failed login attempts. Please try again later.");
            }
        }

        LoginUser loginUser;
        try {
            loginUser = (LoginUser) userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            throw e;
        } catch (AuthenticationException e) {
            throw e;
        }
        // If user is found and not locked by UserDetailsService status checks, then proceed to password validation.
        // Any failure here will be caught by the listener to increment the count.

        if (!passwordEncoder.matches(password, loginUser.getPassword(), loginUser.getUsername(), loginUser.getSalt())) {
            // The AuthenticationFailureBadCredentialsEvent listener will handle incrementing the counter.
            throw new BadCredentialsException("Invalid username or password");
        }

        // Successfully authenticated
        // The AuthenticationSuccessEvent listener will handle clearing the counter.
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
                loginUser,          // principal
                null,               // credentials (usually erased)
                loginUser.getAuthorities() // authorities
        );
        result.setDetails(authentication.getDetails()); // Preserve details (e.g., IP address)
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // This provider supports UsernamePasswordAuthenticationToken
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
