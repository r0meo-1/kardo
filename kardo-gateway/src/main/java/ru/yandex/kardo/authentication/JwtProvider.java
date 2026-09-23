package ru.yandex.kardo.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.yandex.kardo.exception.JwtValidationException;
import ru.yandex.kardo.user.GenerateUserTokenDto;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static ru.yandex.kardo.exception.JwtValidationException.*;

@Slf4j
@Component
public class JwtProvider {
    private final SecretKey jwtAccessSecret;
    private final SecretKey jwtRefreshSecret;

    public JwtProvider(
            @Value("${jwt.secret.access}") String jwtAccessSecret,
            @Value("${jwt.secret.refresh}") String jwtRefreshSecret
    ) {
        this.jwtAccessSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtAccessSecret));
        this.jwtRefreshSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtRefreshSecret));
    }

    public String generateAccessToken(GenerateUserTokenDto user) {
        final LocalDateTime now = LocalDateTime.now();
        final Instant accessExpirationInstant = now.plusMinutes(15).atZone(ZoneId.systemDefault()).toInstant();
        final Date accessExpiration = Date.from(accessExpirationInstant);
        return Jwts.builder()
                .subject(user.getEmail())
                .expiration(accessExpiration)
                .signWith(jwtAccessSecret)
                .claim("roles", user.getRoles())
                .claim("id", user.getId())
                .compact();
    }

    public String generateRefreshToken(GenerateUserTokenDto user) {
        final LocalDateTime now = LocalDateTime.now();
        final Instant refreshExpirationInstant = now.plusDays(30).atZone(ZoneId.systemDefault()).toInstant();
        final Date refreshExpiration = Date.from(refreshExpirationInstant);
        return Jwts.builder()
                .subject(user.getEmail())
                .expiration(refreshExpiration)
                .signWith(jwtRefreshSecret)
                .compact();
    }

    private boolean validateToken(String token, SecretKey secret) {
        getClaims(token, secret);
        return true;
    }

    public boolean validateAccessToken(String accessToken) {
        return validateToken(accessToken, jwtAccessSecret);
    }

    public boolean validateRefreshToken(String refreshToken) {
        return validateToken(refreshToken, jwtRefreshSecret);
    }

    private Claims getClaims(String token, SecretKey secret) {
        try {
            return Jwts.parser()
                    .verifyWith(secret)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException expJwtEx) {
            log.debug("{}: {}", expJwtEx.getClass().getSimpleName(), EXPIRED_JWT_MESSAGE);
            throw new JwtValidationException(JWT_VALIDATION_EXCEPTION_REASON, EXPIRED_JWT_MESSAGE);
        } catch (SignatureException sigEx) {
            log.debug("{}: {}", sigEx.getClass().getSimpleName(), SIGNATURE_EXCEPTION_MESSAGE);
            throw new JwtValidationException(JWT_VALIDATION_EXCEPTION_REASON, SIGNATURE_EXCEPTION_MESSAGE);
        } catch (JwtException | IllegalArgumentException ex) {
            // Parser messages can contain token data; expose only a stable error.
            log.debug("{}: {}", ex.getClass().getSimpleName(), MALFORMED_JWT_MESSAGE);
            throw new JwtValidationException(JWT_VALIDATION_EXCEPTION_REASON, MALFORMED_JWT_MESSAGE);
        }
    }

    public Claims getAccessClaims(String accessToken) {
        return getClaims(accessToken, jwtAccessSecret);
    }

    public Claims getRefreshClaims(String refreshToken) {
        return getClaims(refreshToken, jwtRefreshSecret);
    }

}
