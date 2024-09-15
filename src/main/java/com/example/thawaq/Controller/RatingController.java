package com.example.thawaq.Controller;

import com.example.thawaq.Api.ApiResponse;
import com.example.thawaq.Model.Rating;
import com.example.thawaq.Service.RatingService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/rating")
@RequiredArgsConstructor
public class RatingController {

    private final RatingService ratingService;
    @GetMapping("/get-all")
    public ResponseEntity getAllRatings() {
        return ResponseEntity.status(200).body(ratingService.getAllRatings());
    }

    //User add rating (Jana) //v2
    @PostMapping("/user/add-rating/{userId}/{storeId}")
    public ResponseEntity addRatingToStore(@Valid @RequestBody Rating rating,@PathVariable Integer userId,@PathVariable Integer storeId) {
        ratingService.addRatingFromUserToStore(rating,userId,storeId);
        return ResponseEntity.status(200).body(new ApiResponse("Successfully added User rating to store!"));
    }

    //expert add rating (Jana) v2
    @PostMapping("/expert/add-rating/{expertId}/{storeId}")
    public ResponseEntity addRatingFromExpertToStore(@Valid @RequestBody Rating rating,@PathVariable Integer expertId,@PathVariable Integer storeId) {
        ratingService.addRatingFromExpertToStore(rating,expertId,storeId);
        return ResponseEntity.status(200).body(new ApiResponse("Successfully added Expert rating to store!"));
    }

    @PutMapping("/update-rating/{id}")
    public ResponseEntity updateRatingToStore(@PathVariable Integer id,@Valid @RequestBody Rating rating) {
        ratingService.updateRating(rating,id);
        return ResponseEntity.status(200).body(new ApiResponse("Successfully updated rating!"));}


    @DeleteMapping("/delete-rating/{id}")
    public ResponseEntity deleteRating(@PathVariable Integer id) {
        ratingService.deleteRating(id);
        return ResponseEntity.status(200).body(new ApiResponse("Successfully deleted rating!"));
    }

    ///v2
    @GetMapping("/average-rating-expert/{expertId}")
    public ResponseEntity getAverageRatingExpert(@PathVariable Integer expertId) {
        return ResponseEntity.status(200).body(ratingService.CalculateAverageRatingExpert(expertId));
    }
    ///v2
    @GetMapping("/average-rating-store/{storeId}")
    public ResponseEntity getAverageRatingStore(@PathVariable Integer storeId) {
        ratingService.CalculateAverageStore(storeId);
        return ResponseEntity.status(200).body(ratingService.CalculateAverageStore(storeId));
    }

    @GetMapping("/get-both-by-cleaning-of-rating")  //v2
    public ResponseEntity getBOTHByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getBOTHByCleaningOfRating());
    }
    @GetMapping("/get-restaurant-by-cleaning-of-rating")  //v2
    public ResponseEntity getRestaurantByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getRestaurantByCleaningOfRating());
    }
    @GetMapping("/get-cafe-by-cleaning-of-rating")  //v2
    public ResponseEntity getCafeByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getCafeByCleaningOfRating());
    }
    @GetMapping("/get-branch-both-by-cleaning-of-rating")  //v2
    public ResponseEntity getBranchBOTHByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getBranchBOTHByCleaningOfRating());
    }
    @GetMapping("/get-branch-restaurant-by-cleaning-of-rating")  //v2
    public ResponseEntity getBranchRestaurantByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getBranchRestaurantByCleaningOfRating());
    }
    @GetMapping("/get-branch-cafe-by-cleaning-of-rating")  //v2
    public ResponseEntity getBranchCafeByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getBranchCafeByCleaningOfRating());
    }
    @GetMapping("/get-menu-both-by-cleaning-of-rating")  //v2
    public ResponseEntity getMenuBOTHByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getMenuBOTHByCleaningOfRating());
    }
    @GetMapping("/get-menu-restaurant-by-cleaning-of-rating")  //v2
    public ResponseEntity getMenuRestaurantByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getMenuRestaurantByCleaningOfRating());
    }
    @GetMapping("/get-menu-cafe-by-cleaning-of-rating")  //v2
    public ResponseEntity getMenuCafeByCleaningOfRating()
    {
        return ResponseEntity.status(200).body(ratingService.getMenuCafeByCleaningOfRating());
    }
    @GetMapping("/get-rating-by-latest")  //v2
    public ResponseEntity getRatingByLatest()
    {
        return ResponseEntity.status(200).body(ratingService.getRatingByLatest());
    }
    @GetMapping("/get-rating-by-high")  //v2
    public ResponseEntity getRatingByHigh()
    {
        return ResponseEntity.status(200).body(ratingService.getRatingByHigh());
    }
    @GetMapping("/get-rating-by-low")  //v2
    public ResponseEntity getRatingByLow()
    {
        return ResponseEntity.status(200).body(ratingService.getRatingByLow());
    }
    @GetMapping("/get-rating-by-comment/{comment}")  //v2
    public ResponseEntity getRatingByComment(@PathVariable String comment)
    {
        return ResponseEntity.status(200).body(ratingService.getRatingByComment(comment));
    }

    //V3 Jana
    @GetMapping("/average-rating-store-service/{storeId}")
    public ResponseEntity CalculateAverageServiceStore(@PathVariable Integer storeId) {
        ratingService.CalculateAverageServiceStore(storeId);
        return ResponseEntity.status(200).body(new ApiResponse("successfully Calculate average service!"));
    }
    //V3
    @GetMapping("/top-4-cafes")
    public ResponseEntity getTop4CafesByAverageRating(){
        return ResponseEntity.status(200).body(ratingService.getTop4CafesByAverageRating());}
    //V3
    @GetMapping("/top-4-restaurant")
    public ResponseEntity getTop4RestaurantByAverageRating(){
        return ResponseEntity.status(200).body(ratingService.getTop4RestaurantByAverageRating());}




}
