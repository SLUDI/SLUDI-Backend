package org.example.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.security.OrganizationJwtService;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class OrganizationJwtAuthenticationFilter extends OncePerRequestFilter {

    private final OrganizationJwtService jwtService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    public OrganizationJwtAuthenticationFilter(
            OrganizationJwtService jwtService,
            HandlerExceptionResolver handlerExceptionResolver
    ) {
        this.jwtService = jwtService;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Skip authentication for login and public endpoints
        String requestPath = request.getRequestURI();
        if (requestPath.contains("/api/organization-users/auth/login") ||
                requestPath.contains("/api/organization-users/auth/refresh") ||
                requestPath.contains("/api/organization-users/register")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = authHeader.substring(7);

            // Extract username from token
            final String username = jwtService.extractUsernameFromToken(jwt);

            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

            if (username != null && currentAuth == null) {
                // Validate token
                if (!jwtService.isTokenExpired(jwt)) {

                    // Extract user details from token
                    io.jsonwebtoken.Claims claims = jwtService.validateToken(jwt);

                    // Create authorities from permissions in token
                    @SuppressWarnings("unchecked")
                    List<String> permissions = claims.get("permissions", List.class);

                    List<SimpleGrantedAuthority> authorities = permissions.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

                    // Add admin authority if user is admin
                    Boolean isAdmin = claims.get("isAdmin", Boolean.class);
                    if (Boolean.TRUE.equals(isAdmin)) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                    }

                    // Create authentication token
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            authorities
                    );

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Set authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("Authentication set for user: {} with authorities: {}",
                            username, authorities);
                }
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("Authentication error: {}", e.getMessage());
            handlerExceptionResolver.resolveException(request, response, null, e);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Skip this filter for citizen user endpoints
        String path = request.getRequestURI();
        return path.startsWith("/api/did") ||
                path.startsWith("/api/citizen-user");
    }
}