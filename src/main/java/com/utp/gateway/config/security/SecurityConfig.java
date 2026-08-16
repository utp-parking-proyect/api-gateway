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
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
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

  private static final String PORTAL_PATH = "/gateway/utp-portal/**";
  private static final String PORTAL_CURRENT_USER_PATH = "/gateway/utp-portal/users/me";
  private static final String PORTAL_USER_BY_ID_PATH = "/gateway/utp-portal/users/{id}";
  private static final String PORTAL_CYCLES_PATH = "/gateway/utp-portal/cycles/**";
  private static final String PARKING_REQUEST_PATH = "/gateway/utp-parking/request";
  private static final String PARKING_REQUEST_RESUBMIT_PATH =
      "/gateway/utp-parking/request/{requestId}/resubmit";
  private static final String PARKING_REQUEST_BY_ACCEPTOR_PATH =
      "/gateway/utp-parking/request/acceptor/**";
  private static final String PARKING_REQUEST_BY_APPLICANT_PATH =
      "/gateway/utp-parking/request/applicant/**";
  private static final String PARKING_RESPONSE_PATH = "/gateway/utp-parking/response/**";
  private static final String PARKING_VEHICLES_PATH = "/gateway/utp-parking/vehicles/**";
  private static final String PARKING_UNASSIGNMENT_BY_ACCEPTOR_PATH =
      "/gateway/utp-parking/vehicles/unassignment-requests/acceptor/**";
  private static final String PARKING_UNASSIGNMENT_RESPONSE_PATH =
      "/gateway/utp-parking/vehicles/unassignment-requests/{unassignmentRequestId}";
  private static final String PARKING_CONTROL_ENTRY_PATH = "/gateway/utp-parking/control/entry";
  private static final String PARKING_CONTROL_EXIT_PATH = "/gateway/utp-parking/control/exit";
  private static final String PARKING_CONTROL_AVAILABILITY_PATH =
      "/gateway/utp-parking/control/availability/**";
  private static final String[] APPLICANT_ROLES = {
      Constants.ROLE_STUDENT, Constants.ROLE_TEACHER, Constants.ROLE_ADMINISTRATIVE
  };

  @Bean
  SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                CorsConfigurationSource corsConfigurationSource) {
    return http
        .cors(cors -> cors.configurationSource(corsConfigurationSource))
        .authorizeExchange(auth -> auth
            .pathMatchers(HttpMethod.OPTIONS).permitAll()
            .pathMatchers(
                "/oauth2/**",
                "/authorized",
                "/logout",
                "/gateway/authentication/**"
            ).permitAll()
            .pathMatchers(HttpMethod.GET, PORTAL_CURRENT_USER_PATH).authenticated()
            .pathMatchers(HttpMethod.GET, PORTAL_USER_BY_ID_PATH).authenticated()
            .pathMatchers(HttpMethod.GET, PORTAL_CYCLES_PATH).authenticated()
            .pathMatchers(PORTAL_PATH).hasRole(Constants.ROLE_SAE)
            .pathMatchers(HttpMethod.POST, PARKING_REQUEST_PATH).hasAnyRole(APPLICANT_ROLES)
            .pathMatchers(HttpMethod.POST, PARKING_REQUEST_RESUBMIT_PATH).hasAnyRole(APPLICANT_ROLES)
            .pathMatchers(HttpMethod.GET, PARKING_REQUEST_BY_ACCEPTOR_PATH).hasRole(Constants.ROLE_SAE)
            .pathMatchers(HttpMethod.PATCH, PARKING_RESPONSE_PATH).hasRole(Constants.ROLE_SAE)
            .pathMatchers(HttpMethod.GET, PARKING_UNASSIGNMENT_BY_ACCEPTOR_PATH)
            .hasRole(Constants.ROLE_SAE)
            .pathMatchers(HttpMethod.PATCH, PARKING_UNASSIGNMENT_RESPONSE_PATH)
            .hasRole(Constants.ROLE_SAE)
            .pathMatchers(PARKING_VEHICLES_PATH).hasAnyRole(APPLICANT_ROLES)
            .pathMatchers(HttpMethod.GET, PARKING_REQUEST_BY_APPLICANT_PATH).authenticated()
            .pathMatchers(HttpMethod.POST, PARKING_CONTROL_ENTRY_PATH)
            .hasRole(Constants.ROLE_SECURITY)
            .pathMatchers(HttpMethod.POST, PARKING_CONTROL_EXIT_PATH)
            .hasRole(Constants.ROLE_SECURITY)
            .pathMatchers(HttpMethod.GET, PARKING_CONTROL_AVAILABILITY_PATH).authenticated()
            .anyExchange().authenticated()
        )
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .oauth2ResourceServer(oauth2 -> oauth2
            .bearerTokenConverter(bearerTokenConverter())
            .jwt(jwt -> jwt
                .jwkSetUri("http://localhost:9000/oauth2/jwks")
                .jwtAuthenticationConverter(grantedAuthoritiesExtractor())
            )
        )
        .build();
  }

  private ServerAuthenticationConverter bearerTokenConverter() {
    ServerBearerTokenAuthenticationConverter converter =
        new ServerBearerTokenAuthenticationConverter();
    converter.setAllowUriQueryParameter(true);
    return converter;
  }

  private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
    return jwt -> {
      Collection<String> authorities = jwt.getClaimAsStringList("roles");
      assert authorities != null;
      return Mono.just(new JwtAuthenticationToken(jwt, authorities.stream()
          .map(SimpleGrantedAuthority::new)
          .toList()));
    };
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(List.of("http://localhost:4200"));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
