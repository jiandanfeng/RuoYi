package com.ruoyi.framework.security.service;

import com.ruoyi.common.enums.UserStatus; // Assuming path
import com.ruoyi.common.utils.StringUtils; // For isNull and pattern checks
import com.ruoyi.framework.security.core.LoginUser;
import com.ruoyi.system.domain.SysUser;
import com.ruoyi.system.service.ISysMenuService;
import com.ruoyi.system.service.ISysRoleService;
import com.ruoyi.system.service.ISysUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern; // For email/phone pattern

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    // Basic patterns for phone/email, similar to UserConstants in RuoYi
    // These should ideally come from a shared constants file
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$");
    private static final Pattern MOBILE_PHONE_NUMBER_PATTERN = Pattern.compile(
            "^1[3-9]\\d{9}$");


    @Autowired
    private ISysUserService userService;

    @Autowired
    private ISysRoleService roleService;

    @Autowired
    private ISysMenuService menuService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser user = userService.selectUserByLoginName(username);

        if (StringUtils.isNull(user)) {
            // Try matching as phone number
            if (MOBILE_PHONE_NUMBER_PATTERN.matcher(username).matches()) {
                user = userService.selectUserByPhoneNumber(username);
            }
        }

        if (StringUtils.isNull(user)) {
            // Try matching as email
            if (EMAIL_PATTERN.matcher(username).matches()) {
                user = userService.selectUserByEmail(username);
            }
        }

        if (StringUtils.isNull(user)) {
            log.info("Login user: {} not found.", username);
            throw new UsernameNotFoundException("Login user: " + username + " not found.");
        } else if (UserStatus.DELETED.getCode().equals(user.getDelFlag())) {
            log.info("Login user: {} has been deleted.", username);
            throw new DisabledException("Sorry, your account: " + username + " has been deleted.");
        } else if (UserStatus.DISABLE.getCode().equals(user.getStatus())) {
            log.info("Login user: {} has been disabled.", username);
            throw new LockedException("Sorry, your account: " + username + " has been disabled.");
        }

        return createLoginUser(user);
    }

    public UserDetails createLoginUser(SysUser user) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        if (user.isAdmin()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_admin")); // Standard Spring Security role prefix
            authorities.add(new SimpleGrantedAuthority("*:*:*")); // Wildcard permission
        } else {
            Set<String> roles = roleService.selectRoleKeys(user.getUserId());
            if (roles != null) {
                for (String role : roles) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role)); // Add "ROLE_" prefix
                }
            }
            Set<String> perms = menuService.selectPermsByUserId(user.getUserId());
            if (perms != null) {
                for (String perm : perms) {
                    if (StringUtils.isNotEmpty(perm)) {
                         authorities.add(new SimpleGrantedAuthority(perm));
                    }
                }
            }
        }
        return new LoginUser(user, authorities);
    }
}
