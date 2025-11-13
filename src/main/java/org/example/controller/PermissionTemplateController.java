package org.example.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.ApiResponseDto;
import org.example.dto.CreatePermissionTemplateRequest;
import org.example.dto.PermissionTemplateResponse;
import org.example.service.PermissionTemplateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("api/permission-template")
@Slf4j
@CrossOrigin(origins = "*")
public class PermissionTemplateController {
    @Autowired
    private PermissionTemplateService permissionTemplateService;
    @PostMapping("/create-template")
    public ResponseEntity<ApiResponseDto<PermissionTemplateResponse>> createPermissionTemplate(
            @Valid @RequestBody CreatePermissionTemplateRequest request){
        log.info("Creating permission template: {}",request.getTemplateCode());

        PermissionTemplateResponse response = permissionTemplateService.addPermissionTemplate(request);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDto.<PermissionTemplateResponse>builder()
                        .success(true)
                        .message("Permission template created successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build()
                );
    }
}
