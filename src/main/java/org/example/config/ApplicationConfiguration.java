package org.example.config;

import org.example.repository.CitizenUserRepository;
import org.example.utils.HashUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class ApplicationConfiguration {

    private final CitizenUserRepository citizenUserRepository;

    public ApplicationConfiguration(CitizenUserRepository citizenUserRepository) {
        this.citizenUserRepository = citizenUserRepository;
    }

    /**
     * Custom UserDetailsService — load CitizenUser by DID
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return did -> (org.springframework.security.core.userdetails.UserDetails)
                citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(did));
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * AuthenticationManager bean for handling authentication
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * AuthenticationProvider with custom UserDetailsService
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
}
