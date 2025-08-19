package org.example.controller;

import org.example.service.DeepfakeDetectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/deepfake")
public class DeepfakeDetectionController {
    @Autowired
    private DeepfakeDetectionService deepFakeDetectionService;

    @PostMapping("/face-analyze")
    public String faceAnalyze(@RequestParam("file")MultipartFile file)
    {
        return deepFakeDetectionService.faceAnalyse(file);
    }
}
