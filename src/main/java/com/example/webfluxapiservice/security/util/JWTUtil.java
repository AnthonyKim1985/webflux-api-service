package com.example.webfluxapiservice.security.util;

import com.example.webfluxapiservice.exception.JsonWebTokenNotFoundException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.io.Serializable;
import java.util.Date;

/**
 * @author Anthony Jinhyuk Kim
 * @version 1.0.0
 * @since 2018-10-08
 */
@Component
public class JWTUtil implements Serializable {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expirationTime;

    public static final String CLAIM_KEY_AUTHORITIES = "USER_AUTHORITIES";
    private static final String CLAIM_KEY_NON_EXPIRED = "DOES_NOT_USER_EXPIRE";
    private static final String CLAIM_KEY_IS_ENABLED = "IS_USER_ENABLED";

    public Mono<Boolean> validateToken(String token) {
        return getClaimsFromToken(token)
                .switchIfEmpty(Mono.error(new JsonWebTokenNotFoundException(token)))
                .flatMap(claims -> {
                    final Date tokenExpirationDate = claims.getExpiration();
                    if (!tokenExpirationDate.after(new Date()))
                        return Mono.just(Boolean.FALSE);

                    final Boolean isUserNonExpired = claims.get(CLAIM_KEY_NON_EXPIRED, Boolean.class);
                    final Boolean isUserEnabled = claims.get(CLAIM_KEY_IS_ENABLED, Boolean.class);

                    if (!isUserEnabled || !isUserNonExpired)
                        return Mono.just(Boolean.FALSE);

                    return Mono.just(Boolean.TRUE);
                });
    }

    public Mono<String> getUsernameFromToken(String token) {
        return getClaimsFromToken(token)
                .switchIfEmpty(Mono.error(new JsonWebTokenNotFoundException(token)))
                .flatMap(claims -> Mono.just(claims.getSubject()));
    }

    public Mono<Claims> getClaimsFromToken(String token) {
        return Mono.just(Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody());
    }
}