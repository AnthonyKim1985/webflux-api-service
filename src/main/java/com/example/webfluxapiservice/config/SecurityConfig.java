package com.example.webfluxapiservice.config;

import com.example.webfluxapiservice.constant.Role;
import com.example.webfluxapiservice.security.AuthReactiveAuthenticationManager;
import com.example.webfluxapiservice.security.AuthSecurityContextRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * @author Anthony Jinhyuk Kim
 * @version 1.0.0
 * @since 2018-11-06
 */
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {
    private final AuthSecurityContextRepository securityContextRepository;
    private final AuthReactiveAuthenticationManager authenticationManager;

    @Autowired
    public SecurityConfig(AuthSecurityContextRepository securityContextRepository,
                          AuthReactiveAuthenticationManager authenticationManager) {
        this.securityContextRepository = securityContextRepository;
        this.authenticationManager = authenticationManager;
    }

    @Bean
    public SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                .pathMatchers("/api/v?/admin/**").hasRole(Role.ADMIN.name())
                .pathMatchers("/api/v?/admin/**").authenticated()
                .pathMatchers("/api/v?/manager/**").hasRole(Role.MANAGER.name())
                .pathMatchers("/api/v?/manager/**").authenticated()
                .pathMatchers("/api/v?/staff/**").hasRole(Role.STAFF.name())
                .pathMatchers("/api/v?/staff/**").authenticated()
                .anyExchange().permitAll()
                .and()
                .build();
    }
}
