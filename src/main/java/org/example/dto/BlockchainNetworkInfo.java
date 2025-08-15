package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BlockchainNetworkInfo {
    private String networkName;
    private String channelName;
    private String chaincodeVersion;
    private Integer totalDIDs;
    private Integer totalCredentials;
    private String lastUpdated;
    private String status;
}
