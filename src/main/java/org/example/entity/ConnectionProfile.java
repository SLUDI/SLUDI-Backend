package org.example.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ConnectionProfile {
    private String name;
    private String version;
    private Map<String, Object> client;
    private Map<String, Object> organizations;
    private Map<String, Object> peers;
    private Map<String, Object> certificateAuthorities;
}
