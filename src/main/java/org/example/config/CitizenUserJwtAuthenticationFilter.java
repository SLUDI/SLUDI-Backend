package org.example.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.security.CitizenUserJwtService;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Slf4j
@Component
public class CitizenUserJwtAuthenticationFilter extends OncePerRequestFilter {

    private final CitizenUserJwtService citizenUserJwtService;
    private final UserDetailsService userDetailsService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    public CitizenUserJwtAuthenticationFilter(
            CitizenUserJwtService citizenUserJwtService,
            UserDetailsService userDetailsService,
            HandlerExceptionResolver handlerExceptionResolver
    ) {
        this.citizenUserJwtService = citizenUserJwtService;
        this.userDetailsService = userDetailsService;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Skip this filter for organization endpoints
        String requestPath = request.getRequestURI();
        if (
                requestPath.startsWith("/api/organization")
                        || requestPath.startsWith("/api/organization-users")
                        || requestPath.startsWith("/api/vc")
                        || requestPath.startsWith("/api/did")
                || requestPath.startsWith("api/permission-template")
        ) {
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
            final String didId = citizenUserJwtService.extractDidFromToken(jwt);

            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

            if (didId != null && currentAuth == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(didId);

                if (!citizenUserJwtService.isTokenExpired(jwt)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("Citizen user authenticated: {}", didId);
                }
            }

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("Citizen authentication error: {}", e.getMessage());
            handlerExceptionResolver.resolveException(request, response, null, e);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/organization")
                || path.startsWith("/api/organization-users")
                || path.startsWith("/api/vc")
                || path.startsWith("/api/did")
                || path.startsWith("api/permission-template");
    }
}