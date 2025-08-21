package org.example.authservice.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {
    private static final String ACCESS_TOKEN_COOKIE = "access_token";
    private static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    @Value("${app.security.jwt.access-token-expiration}")
    private Long accessTokenExpiration;

    @Value("${app.security.jwt.refresh-token-expiration}")
    private Long refreshTokenExpiration;

    public void addAccessTokenCookie(HttpServletResponse response, String accessToken) {
        Cookie cookie = createCookie(ACCESS_TOKEN_COOKIE, accessToken, accessTokenExpiration);
        response.addCookie(cookie);
    }

    public void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = createCookie(REFRESH_TOKEN_COOKIE, refreshToken, refreshTokenExpiration);
        response.addCookie(cookie);
    }

    public String getAccessToken(HttpServletRequest request) {
        return getCookieValue(request, ACCESS_TOKEN_COOKIE);
    }

    public String getRefreshToken(HttpServletRequest request) {
        return getCookieValue(request, REFRESH_TOKEN_COOKIE);
    }

    public void clearAccessTokenCookie(HttpServletResponse response) {
        Cookie cookie = createCookie(ACCESS_TOKEN_COOKIE, null, 0L);
        response.addCookie(cookie);
    }

    public void clearRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = createCookie(REFRESH_TOKEN_COOKIE, null, 0L);
        response.addCookie(cookie);
    }

    private Cookie createCookie(String name, String value, Long maxAgeMillis) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge((int) (maxAgeMillis / 1000));
        return cookie;
    }

    private String getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}