package org.example.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("SLUDI API Backend Service")
                        .version("1.0")
                        .description("Comprehensive backend API for SLUDI platform, providing endpoints for user management, credential issuance, and data handling services."))
                .servers(List.of(new Server().url("/")));
    }
}