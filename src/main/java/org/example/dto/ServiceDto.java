package org.example.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonPropertyOrder({
        "id",
        "type",
        "serviceEndpoint"
})
public class ServiceDto {
    private String id;
    private String type;
    private String serviceEndpoint;

    @JsonIgnore
    public boolean isValid() {
        return id != null && !id.isEmpty()
                && type != null && !type.isEmpty()
                && serviceEndpoint != null && !serviceEndpoint.isEmpty();
    }
}