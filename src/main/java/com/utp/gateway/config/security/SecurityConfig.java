package com.utp.gateway.config.security;

import com.utp.gateway.util.constants.Constants;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.List;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {

  private static final String PORTAL_CURRENT_USER_PATH = "/gateway/portal/utp-portal/v1/users/me";

  @Bean
  SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    return http
        .authorizeExchange(auth -> auth
            .pathMatchers(HttpMethod.OPTIONS).permitAll()
            .pathMatchers(
                "/oauth2/**",
                "/authorized",
                "/logout",
                "/gateway/authentication/**"
            ).permitAll()
            .pathMatchers(HttpMethod.GET, PORTAL_CURRENT_USER_PATH)
            .authenticated()
            .pathMatchers("/gateway/portal/**")
            .hasAnyRole(Constants.ROLE_SAE)
            .pathMatchers(HttpMethod.POST, "/gateway/request")
            .hasAnyRole(Constants.ROLE_STUDENT, Constants.ROLE_TEACHER, Constants.ROLE_ADMINISTRATIVE)
            .pathMatchers(HttpMethod.PUT, "/gateway/response")
            .hasAnyRole(Constants.ROLE_SAE)
            .anyExchange().authenticated()
        )
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwkSetUri("http://localhost:9000/oauth2/jwks")
                .jwtAuthenticationConverter(grantedAuthoritiesExtractor())
            )
        )
        .build();
  }

  private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
    return jwt -> {
      Collection<String> authorities = jwt.getClaimAsStringList("roles");
      return Mono.just(new JwtAuthenticationToken(jwt, authorities.stream()
          .map(SimpleGrantedAuthority::new)
          .toList()));
    };
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(List.of("http://localhost:4200"));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
