package com.ruoyi.framework.security.crypto; // Or a similar appropriate package

import org.apache.shiro.crypto.hash.Md5Hash; // Ensure this import is available
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomPasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence rawPassword) {
        // This standard method cannot be correctly implemented for the project's
        // specific hashing algorithm (username + password + salt) without
        // access to username and salt.
        throw new UnsupportedOperationException("Standard encode(rawPassword) is not supported. Use encode(username, salt, rawPassword) instead.");
    }

    /**
     * Encodes the raw password using the project's specific algorithm.
     *
     * @param username    The username.
     * @param salt        The salt.
     * @param rawPassword The raw password to encode.
     * @return The encoded password as a hex string.
     */
    public String encode(String username, String salt, String rawPassword) {
        if (rawPassword == null) {
            // Or handle as appropriate, e.g., return null or throw IllegalArgumentException
            throw new IllegalArgumentException("Raw password cannot be null");
        }
        if (username == null) {
            // Username is part of the hash
             throw new IllegalArgumentException("Username cannot be null for encoding");
        }
        if (salt == null) {
            // Salt is part of the hash
            throw new IllegalArgumentException("Salt cannot be null for encoding");
        }
        return new Md5Hash(username + rawPassword + salt).toHex();
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // This standard method cannot be correctly implemented for the project's
        // specific hashing algorithm without access to username and salt for the rawPassword.
        // The comparison logic needs to be:
        // encodedPassword.equals(encode(username, salt, rawPassword.toString()))
        throw new UnsupportedOperationException("Standard matches(rawPassword, encodedPassword) is not supported. Use matches(rawPassword, encodedPassword, username, salt) instead, typically via a custom AuthenticationProvider.");
    }

    /**
     * Matches a raw password with an encoded password using the project's specific algorithm.
     * This method is intended to be called by a custom AuthenticationProvider that has access
     * to the username and salt associated with the user.
     *
     * @param rawPassword     The raw password to match.
     * @param encodedPassword The encoded password from the database.
     * @param username        The username associated with the user.
     * @param salt            The salt associated with the user.
     * @return True if the passwords match, false otherwise.
     */
    public boolean matches(CharSequence rawPassword, String encodedPassword, String username, String salt) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        if (username == null) {
             return false; // Or throw, but for matching, false is safer
        }
         if (salt == null) {
            return false; // Or throw
        }
        String hashOfRawPassword = new Md5Hash(username + rawPassword.toString() + salt).toHex();
        return encodedPassword.equals(hashOfRawPassword);
    }
}
