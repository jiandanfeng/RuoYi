package com.ruoyi.framework.config;

import com.ruoyi.framework.security.authentication.CustomAuthenticationProvider;
import com.ruoyi.framework.security.crypto.CustomPasswordEncoder;
import com.ruoyi.framework.security.filter.SpringCaptchaValidateFilter; // Added import
import com.ruoyi.framework.security.service.UserDetailsServiceImpl; // For RememberMe
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter; // Added import
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource; // For Persistent RememberMe, if chosen

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) // To enable method-level security annotations
public class SecurityConfig {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired
    private UserDetailsServiceImpl userDetailsService; // For RememberMe

    // Values from application.properties (mirrored from ShiroConfig)
    @Value("${shiro.user.loginUrl:/login}") // Default to /login if not set
    private String loginUrl;

    @Value("${shiro.user.unauthorizedUrl:/unauthorized}") // Default to /unauthorized
    private String unauthorizedUrl;

    // RememberMe settings from ShiroConfig
    @Value("${shiro.cookie.domain:}")
    private String cookieDomain;

    @Value("${shiro.cookie.path:/}")
    private String cookiePath;

    @Value("${shiro.cookie.httpOnly:true}")
    private boolean cookieHttpOnly;

    @Value("${shiro.cookie.maxAge:30}") // days
    private int cookieMaxAgeDays; // Shiro's maxAge is in seconds for cookie, but for remember-me often in days for config

    @Value("${shiro.rememberMe.cipherKey:fCq+/xW488hMTCD+cmJ3aQ==}") // Default key from ShiroConfig
    private String rememberMeKey;
    
    // Session properties for concurrent session control
    @Value("${shiro.session.maxSession:1}")
    private int maxSession;

    @Value("${shiro.session.kickoutAfter:false}")
    private boolean kickoutAfter;

    @Value("${shiro.user.captchaEnabled:true}") // Default to true if not set
    private boolean captchaEnabled;


    // Define CustomPasswordEncoder as a bean
    @Bean
    public CustomPasswordEncoder customPasswordEncoder() {
        return new CustomPasswordEncoder();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        // Redirects to loginUrl with a query parameter indicating error type
        // e.g., /login?error=Invalid+Captcha or /login?error=Bad+credentials
        // The actual message can be derived from the exception message if needed,
        // but for simplicity, a generic error parameter is often used.
        // Or, map specific exceptions to specific error codes/messages.
        SimpleUrlAuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler();
        handler.setDefaultFailureUrl(loginUrl + "?error"); // loginUrl is already a @Value injected field
        // You could also use: handler.setUseForward(true); to forward instead of redirect.
        return handler;
    }

    // Configure AuthenticationManager to use CustomAuthenticationProvider
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(customAuthenticationProvider);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                         PersistentTokenBasedRememberMeServices rememberMeServices,
                                         AuthenticationFailureHandler failureHandler) throws Exception { // Added failureHandler

        // Instantiate the captcha filter
        SpringCaptchaValidateFilter captchaValidateFilter = new SpringCaptchaValidateFilter(
                loginUrl, // The URL for which the filter should be active (login processing URL)
                captchaEnabled,
                failureHandler
        );

        http
            // CSRF Handling: Disable for now, enable later with proper token handling in frontend
            .csrf(csrf -> csrf.disable())
            // Add CaptchaValidateFilter before the UsernamePasswordAuthenticationFilter
            .addFilterBefore(captchaValidateFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(authz -> authz
                .requestMatchers(
                        "/favicon.ico",
                        "/ruoyi.png",
                        "/css/**",
                        "/docs/**",
                        "/fonts/**",
                        "/img/**",
                        "/ajax/**",
                        "/js/**",
                        "/ruoyi/**",
                        "/druid/**",
                        "/captcha/captchaImage**",
                        loginUrl,
                        unauthorizedUrl // Also permit access to unauthorizedUrl page
                ).permitAll()
                .anyRequest().authenticated() // All other requests require authentication
            )
            .formLogin(form -> form
                .loginPage(loginUrl)
                .loginProcessingUrl(loginUrl) // Ensure this matches what Captcha filter expects
                .defaultSuccessUrl("/index") // Or appropriate landing page
                .failureHandler(failureHandler) // Use the same failure handler for form login
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl(loginUrl + "?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me") // Adjust cookie names if different
                .permitAll()
            )
            .rememberMe(remember -> remember
                .rememberMeServices(rememberMeServices)
            )
            .sessionManagement(session -> session
                .maximumSessions(maxSession)
                .maxSessionsPreventsLogin(!kickoutAfter) // if true, new login is prevented; if false (Shiro's kickoutAfter=false), old session is kicked.
                                                        // Spring's maxSessionsPreventsLogin=true means kickoutAfter=false (don't kick previous, prevent new)
                                                        // Spring's maxSessionsPreventsLogin=false means kickoutAfter=true (kick previous, allow new)
                                                        // So, this needs to be: !kickoutAfter
                .expiredUrl(loginUrl + "?kickout=1")
            )
            .exceptionHandling(exceptions -> exceptions
                .accessDeniedPage(unauthorizedUrl)
            );

        return http.build();
    }

    @Bean
    public PersistentTokenBasedRememberMeServices rememberMeServices(DataSource dataSource) {
        // Using PersistentTokenBasedRememberMeServices for more robust remember-me
        // Requires a table: create table persistent_logins (username varchar(64) not null, series varchar(64) primary key, token varchar(64) not null, last_used timestamp not null)
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource); // Inject DataSource
        // tokenRepository.setCreateTableOnStartup(true); // Create table on startup, only for dev/testing

        PersistentTokenBasedRememberMeServices services = new PersistentTokenBasedRememberMeServices(
                rememberMeKey, // Key to identify tokens
                userDetailsService, // UserDetailsService
                tokenRepository // Token repository
        );
        services.setCookieName("remember-me");
        services.setTokenValiditySeconds(cookieMaxAgeDays * 24 * 60 * 60); // Convert days to seconds
        services.getCookie().setPath(cookiePath);
        services.getCookie().setHttpOnly(cookieHttpOnly);
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            services.getCookie().setDomain(cookieDomain);
        }
        return services;
    }
}
