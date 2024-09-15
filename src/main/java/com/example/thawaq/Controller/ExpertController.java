package com.example.thawaq.Controller;

import com.example.thawaq.Api.ApiResponse;
import com.example.thawaq.Service.ExpertService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/expert")
public class ExpertController {
    private final ExpertService expertService;

    @GetMapping("/get-all")
    public ResponseEntity getAllExperts() {
        return ResponseEntity.status(200).body(expertService.getAllExperts());
    }

    @GetMapping("/get-id/{expertId}")
    public ResponseEntity getExpertById(@PathVariable Integer expertId) {
        return ResponseEntity.status(200).body(expertService.getExpertById(expertId));
    }

    @PutMapping("/approve/{expertId}/{rejectId}")
    public ResponseEntity approve (@PathVariable Integer expertId, @PathVariable Integer rejectId) {
        expertService.approveRequest(expertId, rejectId);
        return ResponseEntity.status(200).body(new ApiResponse("Request approved"));
    }

    @PutMapping("/reject/{expertId}/{rejectId}")
    public ResponseEntity reject (@PathVariable Integer expertId, @PathVariable Integer rejectId) {
        expertService.rejectRequest(expertId, rejectId);
        return ResponseEntity.status(200).body(new ApiResponse("Request rejected"));
    }

    @GetMapping("/top-4")
    public ResponseEntity getTop4Experts() {
        return ResponseEntity.status(200).body(expertService.findTop4Experts());
    }

}
