package org.example.authservice.service.impl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authservice.dto.auth.LoginRequest;
import org.example.authservice.dto.auth.RegistrationRequest;
import org.example.authservice.exception.BusinessException;
import org.example.authservice.dto.error.ErrorCode;
import org.example.authservice.mapper.UserMapper;
import org.example.authservice.model.User;
import org.example.authservice.repository.UserRepository;
import org.example.authservice.security.CookieUtils;
import org.example.authservice.security.JwtService;
import org.example.authservice.service.AuthService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final CookieUtils cookieUtils;
    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public void register(RegistrationRequest request, HttpServletResponse response) {
        User user = userMapper.toUser(request);
        log.debug("Saving user {}", user);

        userRepository.save(user);

        cookieUtils.addAccessTokenCookie(response,
                jwtService.generateAccessToken(user.getEmail(), user.getId())
        );
        cookieUtils.addRefreshTokenCookie(response,
                jwtService.generateRefreshToken(user.getEmail(), user.getId())
        );
    }

    @Override
    public void login(LoginRequest request, HttpServletResponse response) {
        var authToken = new UsernamePasswordAuthenticationToken(request.email(), request.password());
        authenticationManager.authenticate(authToken);

        var user = userRepository.findByEmailIgnoreCase(request.email())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        cookieUtils.addAccessTokenCookie(response,
                jwtService.generateAccessToken(user.getEmail(), user.getId())
        );
        cookieUtils.addRefreshTokenCookie(response,
                jwtService.generateRefreshToken(user.getEmail(), user.getId())
        );
    }

    @Override
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = cookieUtils.getRefreshToken(request);
        if (refreshToken == null) {
            throw new RuntimeException("Refresh token missing");
        }

        cookieUtils.addAccessTokenCookie(response,
                jwtService.refreshAccessToken(refreshToken)
        );
        cookieUtils.addRefreshTokenCookie(response, refreshToken);
    }

    @Override
    public void logout(HttpServletResponse response) {
        cookieUtils.clearAccessTokenCookie(response);
        cookieUtils.clearRefreshTokenCookie(response);
    }

    @Override
    public Long validateToken(HttpServletRequest request) {
        String accessToken = cookieUtils.getAccessToken(request);
        if (accessToken != null && jwtService.isTokenValid(accessToken, jwtService.extractEmail(accessToken))) {
            return jwtService.extractUserId(accessToken);
        }
        throw new BusinessException(ErrorCode.INVALID_TOKEN);
    }
}