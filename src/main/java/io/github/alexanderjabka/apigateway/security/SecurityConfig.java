package io.github.alexanderjabka.apigateway.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

import javax.crypto.SecretKey;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public ReactiveJwtDecoder jwtDecoder(@Value("${jwt.secret}") String secret) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        return NimbusReactiveJwtDecoder.withSecretKey(key).build();
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex
                        .pathMatchers("/auth/login", "/auth/register").permitAll()
                        .pathMatchers("/actuator/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}))
                .build();
    }
}


