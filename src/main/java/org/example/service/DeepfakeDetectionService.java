package org.example.service;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class DeepfakeDetectionService {
    private final WebClient webClient;
    private final int MAX_FRAMES = 2;


    public DeepfakeDetectionService(@Value("${fastapi.base-url}") String fastApiBaseUrl, WebClient.Builder builder) {
        // Increase the max buffer size
        ExchangeStrategies strategies = ExchangeStrategies.builder()
                .codecs(configurer -> configurer.defaultCodecs()
                        .maxInMemorySize(16*1024*1024))//16MB
                .build();

        this.webClient = builder
                .baseUrl(fastApiBaseUrl)
                .exchangeStrategies(strategies)
                .build();
    }

    public String faceAnalyse(MultipartFile multipartFile){
        return webClient.post()
                .uri(uriBuilder -> uriBuilder
                        .path("/analyze")
                        .queryParam("max_frames", MAX_FRAMES)
                        .build())
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(BodyInserters.fromMultipartData("file",multipartFile.getResource()))
                .retrieve()
                .bodyToMono(String.class)
                .block();

    }
}


