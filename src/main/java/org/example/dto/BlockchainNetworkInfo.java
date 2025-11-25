package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BlockchainNetworkInfo {
    private String networkName;
    private String channelName;
    private String chaincodeVersion;
    private Integer totalDIDs;
    private Integer totalCredentials;
    private String lastUpdated;
    private String status;
}
