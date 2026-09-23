package ru.yandex.kardo.authentication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import ru.yandex.kardo.authentication.filter.FilterChainExceptionHandler;
import ru.yandex.kardo.authentication.filter.JwtFilter;
import ru.yandex.kardo.exception.JwtValidationException;
import ru.yandex.kardo.user.GenerateUserTokenDto;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtProviderTest {
    private SecretKey accessKey;
    private JwtProvider provider;

    @BeforeEach
    void setUp() {
        accessKey = Jwts.SIG.HS256.key().build();
        SecretKey refreshKey = Jwts.SIG.HS256.key().build();
        provider = new JwtProvider(Encoders.BASE64.encode(accessKey.getEncoded()),
                Encoders.BASE64.encode(refreshKey.getEncoded()));
    }

    @Test
    void generatedTokensRemainUsableAndKeysAreSeparated() {
        GenerateUserTokenDto user = GenerateUserTokenDto.builder()
                .id(42L).email("test@example.invalid").roles(Set.of()).build();
        String access = provider.generateAccessToken(user);
        String refresh = provider.generateRefreshToken(user);
        assertThat(provider.validateAccessToken(access)).isTrue();
        assertThat(provider.getAccessClaims(access).getSubject()).isEqualTo(user.getEmail());
        assertThat(provider.getAccessClaims(access).get("id", Long.class)).isEqualTo(42L);
        assertThat(provider.validateRefreshToken(refresh)).isTrue();
        assertThat(provider.getRefreshClaims(refresh).getSubject()).isEqualTo(user.getEmail());
        assertRejected(refresh);
        assertThatThrownBy(() -> provider.validateRefreshToken(access))
                .isInstanceOf(JwtValidationException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "not-a-jwt", "a.b.c"})
    void invalidInputUsesTheDomainException(String token) {
        assertRejected(token);
        assertThatThrownBy(() -> provider.validateRefreshToken(token))
                .isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> provider.getRefreshClaims(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void unsignedTokenIsRejected() {
        assertRejected(Jwts.builder().subject("test@example.invalid").compact());
    }

    @Test
    void signedNonClaimsPayloadIsRejected() {
        assertRejected(Jwts.builder().content("not JSON claims").signWith(accessKey).compact());
    }

    @Test
    void expiredTokenUsesTheDomainException() {
        assertRejected(Jwts.builder().subject("test@example.invalid")
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(accessKey).compact());
    }

    @Test
    void tokenNotYetValidUsesTheDomainException() {
        assertRejected(Jwts.builder().subject("test@example.invalid")
                .notBefore(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(accessKey).compact());
    }

    @Test
    void invalidBearerHeaderReturnsForbiddenThroughTheFilterChain() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer "
                + Jwts.builder().subject("test@example.invalid").compact());
        MockHttpServletResponse response = new MockHttpServletResponse();
        new FilterChainExceptionHandler().doFilter(request, response,
                (req, res) -> new JwtFilter(provider).doFilter(req, res,
                        (acceptedRequest, acceptedResponse) -> {
                            throw new AssertionError("Invalid token reached the application");
                        }));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getContentAsString()).contains("403 FORBIDDEN");
    }

    private void assertRejected(String token) {
        assertThatThrownBy(() -> provider.validateAccessToken(token))
                .isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> provider.getAccessClaims(token))
                .isInstanceOf(JwtValidationException.class);
    }
}
