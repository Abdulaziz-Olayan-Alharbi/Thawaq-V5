package com.example.thawaq.Controller;

import com.example.thawaq.Api.ApiResponse;
import com.example.thawaq.Model.Client;
import com.example.thawaq.Model.Store;
import com.example.thawaq.Service.StoreService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/store")
public class StoreController {

    private final StoreService storeService;

    @GetMapping("/get")
    public ResponseEntity getStores()
    {
        return ResponseEntity.status(200).body(storeService.getStores());
    }


    @PostMapping("/add/{storeID}") //v2
    public ResponseEntity addStore(@PathVariable Integer storeID,@Valid@RequestBody Store store)
    {
        storeService.addStore(storeID,store);
        return ResponseEntity.status(200).body(new ApiResponse("Store added"));
    }


    @PutMapping("/update/{id}")
    public ResponseEntity updateStore(@PathVariable Integer id,@Valid@RequestBody Store store)
    {
        storeService.updateStore(id, store);
        return ResponseEntity.status(200).body("Store updated");/*new ApiResponse("Store updated")*/
    }


    @DeleteMapping("/delete/{id}")
    public ResponseEntity deleteStore(@PathVariable Integer id)
    {
        storeService.deleteStore(id);
        return ResponseEntity.status(200).body("Store deleted");/*new ApiResponse("Store deleted")*/
    }

    //(Jana) v2
    //Get type of activity based on name of type of activity
    @GetMapping("/get-typeOfActivity/{typeOfActivity}")
    public ResponseEntity findStoreByTypeOfActivity(@PathVariable String typeOfActivity){
        return ResponseEntity.status(200).body(storeService.findStoreByTypeOfActivity(typeOfActivity));
    }

    @GetMapping("/get-best-quality-cafes-name/{name}")
    public ResponseEntity findStoreByBestQualityCafesName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getBestQualityForCafesByName(name));
    }


    @GetMapping("/get-best-quality-restaurant-name/{name}")
    public ResponseEntity findStoreByBestQualityRestaurantsName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getBestQualityForRestaurantsByName(name));
    }

    @GetMapping("/get-best-quality-both-name/{name}")
    public ResponseEntity findStoreByBestQualityBothName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getBestQualityForBothByName(name));
    }

    @GetMapping("/get-best-quality-cafes-category/{category}")
    public ResponseEntity findStoreByBestQualityCafesCategory(@PathVariable String category){
        return ResponseEntity.status(200).body(storeService.getBestQualityForCafesByDishType(category));
    }

    @GetMapping("/get-best-quality-restaurant-category/{category}")
    public ResponseEntity findStoreByBestQualityRestaurantCategory(@PathVariable String category){
        return ResponseEntity.status(200).body(storeService.getBestQualityForRestaurantByDishType(category));
    }

    @GetMapping("/get-best-quality-both-category/{category}")
    public ResponseEntity findStoreByBestQualityBothCategory(@PathVariable String category){
        return ResponseEntity.status(200).body(storeService.getBestQualityForBothByDishType(category));
    }

    @GetMapping("/get-best-quality-cafes-city/{city}")
    public ResponseEntity findStoreByBestQualityCafesCity(@PathVariable String city){
        return ResponseEntity.status(200).body(storeService.getBestQualityForCafesByCity(city));
    }

    @GetMapping("/get-best-quality-restaurant-city/{city}")
    public ResponseEntity findStoreByBestQualityRestaurantCity(@PathVariable String city){
        return ResponseEntity.status(200).body(storeService.getBestQualityForRestaurantByCity(city));
    }

    @GetMapping("/get-best-quality-both-city/{city}")
    public ResponseEntity findStoreByBestQualityBothCity(@PathVariable String city){
        return ResponseEntity.status(200).body(storeService.getBestQualityForBothByCity(city));
    }

    @GetMapping("/get-restaurants-you-like/{clientId}")
    public ResponseEntity findRestaurantYouLike(@PathVariable Integer clientId){
        return ResponseEntity.status(200).body(storeService.getRestaurantsYouLike(clientId));
    }

    @GetMapping("/get-cafes-you-like/{clientId}")
    public ResponseEntity findCafesYouLike(@PathVariable Integer clientId){
        return ResponseEntity.status(200).body(storeService.getCafesYouLike(clientId));
    }

    @GetMapping("/get-restaurants-you-may-like/{clientId}")
    public ResponseEntity findRestaurantYouMayLike(@PathVariable Integer clientId){
        return ResponseEntity.status(200).body(storeService.getRestaurantYouMayLike(clientId));
    }

    @GetMapping("/get-cafes-you-may-like/{clientId}")
    public ResponseEntity findCafesYouMayLike(@PathVariable Integer clientId){
        return ResponseEntity.status(200).body(storeService.getCafesYouMayLike(clientId));
    }

    ///////v3
    @GetMapping("/get-lowes-cost-cafes-name/{name}")
    public ResponseEntity findStoreByLowesCostCafesName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getLowestCostForCafesByName(name));
    }
    ///////v3
    @GetMapping("/get-lowes-cost-restaurant-name/{name}")
    public ResponseEntity findStoreByLowesCostRestaurantsName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getLowestCostRestaurantsByName(name));
    }
    ////////v3
    @GetMapping("/get-lowes-cost-both-name/{name}")
    public ResponseEntity findStoreByLowesCostBothName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getLowestCostForBothByName(name));
    }
    /////////v3
    @GetMapping("/get-lowes-cost-cafes-category/{category}")
    public ResponseEntity findStoreByLowesCostCafesCategory(@PathVariable String category){
        return ResponseEntity.status(200).body(storeService.getLowestCostForCafesByDishType(category));
    }
    /////////v3
    @GetMapping("/get-lowes-cost-restaurant-category/{category}")
    public ResponseEntity findStoreByLowesCostRestaurantCategory(@PathVariable String category){
        return ResponseEntity.status(200).body(storeService.getLowestCostForRestaurantByDishType(category));
    }
    /////////v3
    @GetMapping("/get-lowes-cost-both-category/{category}")
    public ResponseEntity findStoreByLowesCostBothCategory(@PathVariable String category){
        return ResponseEntity.status(200).body(storeService.getLowestCostForBothByDishType(category));
    }
    //////////v3
    @GetMapping("/get-lowes-cost-cafes-city/{city}")
    public ResponseEntity findStoreByLowesCostCafesCity(@PathVariable String city){
        return ResponseEntity.status(200).body(storeService.getLowestCostForCafesByCity(city));
    }
    ///////////v3
    @GetMapping("/get-lowes-cost-restaurant-city/{city}")
    public ResponseEntity findStoreByLowesCostRestaurantCity(@PathVariable String city){
        return ResponseEntity.status(200).body(storeService.getLowestCostForRestaurantByCity(city));
    }
    ///////////v3
    @GetMapping("/get-lowes-cost-both-city/{city}")
    public ResponseEntity findStoreByLowesCostBothCity(@PathVariable String city){
        return ResponseEntity.status(200).body(storeService.getLowestCostForBothByCity(city));
    }

    //V3
    @GetMapping("/get-best-service-cafes-name/{name}")
    public ResponseEntity getBestServiceForCafesByName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getBestServiceForCafesByName(name));
    }
    //V3
    @GetMapping("/get-best-service-restaurant-name/{name}")
    public ResponseEntity getBestServiceForRestaurantByName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getBestServiceForRestaurantByName(name));}
    //V3
    @GetMapping("/get-best-service-both-name/{name}")
    public ResponseEntity getBestServiceForBothByName(@PathVariable String name){
        return ResponseEntity.status(200).body(storeService.getBestServiceForBothByName(name));
    }
    //V3
    @GetMapping("/get-best-service-cafes-categoryName/{categoryName}")
    public ResponseEntity getBestServiceForCafesByCategoryName(@PathVariable String categoryName){
        return ResponseEntity.status(200).body(storeService.getBestServiceForCafesByCategoryName(categoryName));
    }
    //V3
    @GetMapping("/get-best-service-restaurant-categoryName/{categoryName}")
    public ResponseEntity getBestServiceForRestaurantByCategoryName(@PathVariable String categoryName){
        return ResponseEntity.status(200).body(storeService.getBestServiceForRestaurantByCategoryName(categoryName));
    }
    //V3
    @GetMapping("/get-best-service-both-categoryName/{categoryName}")
    public ResponseEntity  getBestServiceForBothByCategoryName(@PathVariable String categoryName){
        return ResponseEntity.status(200).body(storeService.getBestServiceForBothByCategoryName(categoryName));
    }
    //V3
    @GetMapping("/get-best-service-cafe-cityName/{cityName}")
    public ResponseEntity getBestServiceForCafeByCityName(@PathVariable String cityName){
        return ResponseEntity.status(200).body(storeService.getBestServiceForCafeByCityName(cityName));
    }

    //V3
    @GetMapping("/get-best-service-restaurant-cityName/{cityName}")
    public ResponseEntity getBestServiceForRestaurantByCityName(@PathVariable String cityName){
        return ResponseEntity.status(200).body(storeService.getBestServiceForRestaurantByCityName(cityName));
    }
    //v3
    @GetMapping("/get-best-service-both-cityName/{cityName}")
    public ResponseEntity  getBestServiceForBothByCityName(@PathVariable String cityName){
        return ResponseEntity.status(200).body(storeService.getBestServiceForBothByCityName(cityName));
    }



}
