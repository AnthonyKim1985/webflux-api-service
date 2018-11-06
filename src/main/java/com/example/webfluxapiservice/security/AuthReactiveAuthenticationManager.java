package com.example.webfluxapiservice.security;

import com.example.webfluxapiservice.exception.InvalidAuthTokenException;
import com.example.webfluxapiservice.security.util.JWTUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Anthony Jinhyuk Kim
 * @version 1.0.0
 * @since 2018-10-08
 */
@Slf4j
@Component
public class AuthReactiveAuthenticationManager implements ReactiveAuthenticationManager {
    private final JWTUtil jwtUtil;

    @Autowired
    public AuthReactiveAuthenticationManager(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        final String authorityToken = authentication.getCredentials().toString();
        return jwtUtil.validateToken(authorityToken)
                .switchIfEmpty(Mono.error(new InvalidAuthTokenException(authorityToken)))
                .flatMap(isValidToken -> {
                    if (!isValidToken)
                        return Mono.error(new InvalidAuthTokenException(authorityToken));

                    return jwtUtil.getUsernameFromToken(authorityToken)
                            .switchIfEmpty(Mono.error(new InvalidAuthTokenException(authorityToken)))
                            .flatMap(username -> jwtUtil.getClaimsFromToken(authorityToken)
                                    .flatMap(claims -> {
                                        final List grantedAuthorityList = claims.get(JWTUtil.CLAIM_KEY_AUTHORITIES, List.class);
                                        final List<String> roleList = new ArrayList<>();
                                        for (Object grantedAuthority : grantedAuthorityList)
                                            roleList.add((String) ((LinkedHashMap) grantedAuthority).get("authority"));

                                        return Mono.just(new UsernamePasswordAuthenticationToken(username, null,
                                                roleList.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())));
                                    })
                            );
                });
    }
}
