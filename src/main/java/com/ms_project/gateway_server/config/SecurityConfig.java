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

    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http){
        return http
                            .cors(cors -> cors
                                            .configurationSource(request -> new CorsConfiguration()
                                                            .applyPermitDefaultValues()))
                            .csrf(csrf -> csrf
                                            .disable())
                            .authorizeExchange(exchange -> exchange
                                            .pathMatchers(HttpMethod.POST, 
                                                                "/keycloak-server/realms/MPRealm/protocol/openid-connect/token")
                                            .permitAll()
                                            //.pathMatchers(HttpMethod.GET, "//**")
                                            //.hasRole("VENDEDOR")
                                            .anyExchange().authenticated())
                            .oauth2ResourceServer(oauth -> oauth
                                            .jwt(jwt -> jwt.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter()))) 
                                            
                            .build();
    }
    
}
