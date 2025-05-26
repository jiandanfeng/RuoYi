package com.ruoyi.framework.security.filter;

import com.google.code.kaptcha.Constants; // KAPTCHA_SESSION_KEY
// import com.ruoyi.common.constant.ShiroConstants; // Not strictly needed if we hardcode "validateCode"
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
// import org.springframework.stereotype.Component; // Not using @Component for this filter
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class SpringCaptchaValidateFilter extends OncePerRequestFilter {

    private boolean captchaEnabled;
    private String loginProcessingUrl;
    private AuthenticationFailureHandler failureHandler;

    private static final String DEFAULT_VALIDATE_CODE_PARAMETER = "validateCode"; // Matches ShiroConstants.CURRENT_VALIDATECODE
    private static final String KAPTCHA_SESSION_KEY_NAME = Constants.KAPTCHA_SESSION_KEY;

    public SpringCaptchaValidateFilter(String loginProcessingUrl, boolean captchaEnabled, AuthenticationFailureHandler failureHandler) {
        if (loginProcessingUrl == null) {
            throw new IllegalArgumentException("loginProcessingUrl cannot be null");
        }
        if (failureHandler == null) {
            throw new IllegalArgumentException("failureHandler cannot be null");
        }
        this.loginProcessingUrl = loginProcessingUrl;
        this.captchaEnabled = captchaEnabled;
        this.failureHandler = failureHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (captchaEnabled && "POST".equalsIgnoreCase(request.getMethod()) && loginProcessingUrl.equals(request.getRequestURI())) {
            String submittedCaptcha = request.getParameter(DEFAULT_VALIDATE_CODE_PARAMETER);
            HttpSession session = request.getSession(false); // Do not create session if it doesn't exist

            String sessionCaptcha = null;
            if (session != null) {
                sessionCaptcha = (String) session.getAttribute(KAPTCHA_SESSION_KEY_NAME);
            }

            if (sessionCaptcha == null || !StringUtils.hasText(submittedCaptcha) || !submittedCaptcha.equalsIgnoreCase(sessionCaptcha)) {
                if (session != null) {
                    session.removeAttribute(KAPTCHA_SESSION_KEY_NAME); // Prevent reuse
                }
                failureHandler.onAuthenticationFailure(request, response, new AuthenticationServiceException("Invalid Captcha"));
                return; // Stop filter chain execution
            }
            
            // Captcha is valid, clear it from session to prevent reuse
            if (session != null) {
                session.removeAttribute(KAPTCHA_SESSION_KEY_NAME);
            }
        }

        filterChain.doFilter(request, response);
    }

    // Setters might be useful if properties can change post-construction,
    // but constructor injection is generally preferred for required dependencies.
    public void setCaptchaEnabled(boolean captchaEnabled) {
        this.captchaEnabled = captchaEnabled;
    }

    // No setter for loginProcessingUrl or failureHandler as they are critical and should be set at construction.
}
