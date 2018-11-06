package com.example.webfluxapiservice.security;

import com.example.webfluxapiservice.exception.HttpHeaderNotFoundException;
import com.example.webfluxapiservice.exception.InvalidAuthTokenException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author Anthony Jinhyuk Kim
 * @version 1.0.0
 * @since 2018-10-08
 */
@Component
public class AuthSecurityContextRepository implements ServerSecurityContextRepository {
    private static final String AUTHORIZATION_PREFIX = "Bearer ";

    private final AuthReactiveAuthenticationManager authenticationManager;

    @Autowired
    public AuthSecurityContextRepository(AuthReactiveAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.error(new UnsupportedOperationException("The save is not supported yet."));
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        final String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(AUTHORIZATION_PREFIX))
            return Mono.error(new HttpHeaderNotFoundException(HttpHeaders.AUTHORIZATION));

        final String token = authorization.substring(AUTHORIZATION_PREFIX.length());
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(token, token))
                .switchIfEmpty(Mono.error(new InvalidAuthTokenException(token)))
                .map(SecurityContextImpl::new);
    }
}
