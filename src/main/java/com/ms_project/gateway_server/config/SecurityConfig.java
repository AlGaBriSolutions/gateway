package com.ms_project.gateway_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

        String[] roles = {"ROLE_CLIENTE", "ROLE_PROVEEDOR"};

        @Bean
        SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
                return http
                                .cors(cors -> cors
                                                .configurationSource(request -> new CorsConfiguration()
                                                                .applyPermitDefaultValues()))
                                .csrf(csrf -> csrf
                                                .disable())
                                .authorizeExchange(exchange -> exchange
                                                // Allow authentication endpoint
                                                .pathMatchers(HttpMethod.POST, "/keycloak-server/realms/myrealm/protocol/openid-connect/token") //Endpoint para hacer login. Envía tokens de JWT
                                                .permitAll()

                                                // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.POST, "/ms-item/**")
                                                .hasAnyRole("PROVEEDDOR", "CLIENTE")

                                                 // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.GET, "/ms-orden/Orden/**")
                                                .hasAnyRole("PROVEEDDOR", "CLIENTE")

                                                // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.POST, "/ms-orden/Orden/**")
                                                .hasRole("ROLE_PROVEEDOR")
                                                

                                                // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.PUT, "/ms-orden/Orden/**")
                                                .hasAnyRole("PROVEEDDOR", "CLIENTE")

                                                // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.DELETE, "/ms-orden/Orden/**")
                                                .hasAnyRole("PROVEEDDOR", "CLIENTE")

                                                // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.GET, "/ms-usuario/**")
                                                .hasAnyRole("PROVEEDDOR", "CLIENTE")

                                                // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.POST, "/ms-usuario/Usuario/**")
                                                .hasAnyRole("PROVEEDDOR", "CLIENTE")

                                                // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.PUT, "/ms-usuario/Usuario/**")
                                                .hasAnyRole("PROVEEDDOR", "CLIENTE")

                                                // Allow access to simple microservice to certain roles
                                                .pathMatchers(HttpMethod.DELETE, "/ms-usuario/Usuario/**")
                                                .hasAnyRole("PROVEEDDOR", "CLIENTE")

                                                // For any other request, the user must be authenticated
                                                .anyExchange().authenticated())
                                // Configures JWT to properly process Keycloak tokens
                                .oauth2ResourceServer(oauth2 -> oauth2
                                                .jwt(jwt -> jwt.jwtAuthenticationConverter(
                                                                new KeycloakJwtAuthenticationConverter())))
                                .build();
        }

}
