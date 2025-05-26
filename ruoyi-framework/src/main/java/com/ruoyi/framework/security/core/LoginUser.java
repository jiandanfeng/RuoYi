package com.ruoyi.framework.security.core;

import com.ruoyi.system.domain.SysUser; // Assuming this is the correct path
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;

public class LoginUser implements UserDetails {

    private static final long serialVersionUID = 1L; // Good practice for Serializable

    private final SysUser sysUser;
    private final Set<GrantedAuthority> authorities;

    public LoginUser(SysUser sysUser, Set<GrantedAuthority> authorities) {
        if (sysUser == null) {
            throw new IllegalArgumentException("SysUser cannot be null");
        }
        this.sysUser = sysUser;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return sysUser.getPassword();
    }

    @Override
    public String getUsername() {
        return sysUser.getLoginName();
    }

    // For simplicity, these are true. Actual checks for locked/disabled status
    // are done in UserDetailsServiceImpl by throwing specific exceptions.
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // This is true because UserDetailsServiceImpl will throw LockedException
        // if user.getStatus() is 'disabled'. If it doesn't throw, account is not locked.
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        // This is true because UserDetailsServiceImpl will throw DisabledException
        // if user.getDelFlag() is 'deleted'. If it doesn't throw, account is enabled.
        return true;
    }

    // Custom methods
    public String getSalt() {
        return sysUser.getSalt();
    }

    public SysUser getSysUser() {
        return sysUser;
    }
}
