package org.example.utils;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import lombok.Data;

@Configuration
@ConfigurationProperties(prefix = "fabric")
@Data
public class FabricProperties {
    private String basePath;
    private Org1 org1 = new Org1();
    private Org2 org2 = new Org2();

    @Data
    public static class Org1 {
        private String mspId;
        private String channelName;
        private String chaincodeName;
        private String peerEndpoint;
        private String ordererEndpoint;
        private String caEndpoint;
    }

    @Data
    public static class Org2 {
        private String mspId;
        private String channelName;
        private String chaincodeName;
        private String peerEndpoint;
        private String ordererEndpoint;
        private String caEndpoint;
    }
}
