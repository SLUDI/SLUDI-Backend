package org.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

        private final AuthenticationProvider authenticationProvider;
        private final CitizenUserJwtAuthenticationFilter citizenUserJwtAuthenticationFilter;
        private final OrganizationJwtAuthenticationFilter organizationJwtAuthenticationFilter;

        // Citizen user public endpoints
        private static final String[] CITIZEN_PUBLIC_URLS = {
                        "/auth/**",
                        "/swagger-ui/**",
                        "/v3/api-docs/**",
                        "/swagger-ui.html",
                        "/swagger-resources/**",
                        "/webjars/**",
                        "/api/wallet/verify-did",
                        "/api/appointments/**",
                        "/api/blockchain/**",
                        "/api/citizen-user/register",
                        "/api/deepfake/**",
                        "/api/did/**",
                        "/api/wallet/**",
                        "api/permission-template/**"
        };

        // Organization user public endpoints
        private static final String[] ORGANIZATION_PUBLIC_URLS = {
                        "/api/organization-users/auth/login",
                        "/api/organization-users/auth/refresh",
                        "/api/organization-users/register",
                        "/api/organization-users/verify-permission",
                        "/api/organization-users/organization/{organizationId}/roles/initialize",
                        "/api/citizen-user/register",
        };

        // Citizen user private endpoints (require authentication)
        private static final String[] CITIZEN_PRIVATE_URLS = {
                        "/api/wallet/retrieve",
                        "/api/wallet/driving-license/request/{sessionId}",
                        "/api/wallet/driving-license/presentation/{sessionId}"
        };

        // Organization user private endpoints (require authentication)
        private static final String[] ORGANIZATION_PRIVATE_URLS = {
                        "/api/organization/**",
                        "/api/organization-users/**",
                        "/api/permission-templates/**",
                        "/api/organization-users/auth/change-password",
                        "/api/vc/**",
                        "/api/did/register",
                        "/api/citizen-user/**",
                        "/api/sync/**"
        };

        public SecurityConfiguration(
                        OrganizationJwtAuthenticationFilter organizationJwtAuthenticationFilter,
                        AuthenticationProvider authenticationProvider,
                        CitizenUserJwtAuthenticationFilter citizenUserJwtAuthenticationFilter) {
                this.citizenUserJwtAuthenticationFilter = citizenUserJwtAuthenticationFilter;
                this.organizationJwtAuthenticationFilter = organizationJwtAuthenticationFilter;
                this.authenticationProvider = authenticationProvider;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(AbstractHttpConfigurer::disable)
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                                .authorizeHttpRequests(auth -> auth
                                                // Permit all citizen public URLs
                                                .requestMatchers(CITIZEN_PUBLIC_URLS).permitAll()

                                                // Permit all organization public URLs
                                                .requestMatchers(ORGANIZATION_PUBLIC_URLS).permitAll()

                                                // Require authentication for citizen private URLs
                                                .requestMatchers(CITIZEN_PRIVATE_URLS).authenticated()

                                                // Require authentication for organization URLs
                                                .requestMatchers(ORGANIZATION_PRIVATE_URLS).authenticated()

                                                // Deny everything else
                                                .anyRequest().denyAll())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authenticationProvider(authenticationProvider)
                                // Add citizen JWT filter first
                                .addFilterBefore(citizenUserJwtAuthenticationFilter,
                                                UsernamePasswordAuthenticationFilter.class)
                                // Add organization JWT filter after citizen filter
                                .addFilterAfter(organizationJwtAuthenticationFilter,
                                                UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(List.of("*"));
                configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
                configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                configuration.setExposedHeaders(List.of("Authorization"));

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);

                return source;
        }
}