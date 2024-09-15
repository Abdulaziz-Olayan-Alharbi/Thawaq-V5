package com.example.thawaq.Service;

import com.example.thawaq.Api.ApiException;
import com.example.thawaq.Model.*;
import com.example.thawaq.Repository.*;
import lombok.RequiredArgsConstructor;
import org.hibernate.mapping.Collection;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class StoreService {

    private final StoreRepository storeRepository;
    private final StoreAdminRepository storeAdminRepository;
    private final RatingService ratingService;
    private final CategoryRepository categoryRepository;
    private final MenuRepository menuRepository;
    private final AddressRepository addressRepository;
    private final FavoriteRepository favoriteRepository;
    private final ClientRepository clientRepository;


    public List<Store> getStores()
    {
        return storeRepository.findAll();
    }

    public void addStore(Integer sID,Store store) // v2
    {
        StoreAdmin sa = storeAdminRepository.findStoreAdminById(sID);
        if(sa == null)
        {
            throw new ApiException("Store not found");
        }
        store.setActive(false);
        storeRepository.save(store);
        sa.setStore(store);
        storeAdminRepository.save(sa);
    }

    public void updateStore(Integer id,Store store)
    {
        Store s = storeRepository.findStoreById(id);
        if(s == null)
        {
//            throw new ApiException("Store not found");
        }
        s.setName(store.getName());
        s.setTypeOfActivity(store.getTypeOfActivity());
        s.setPhoneNumber(store.getPhoneNumber());
        s.setCommercialRegister(store.getCommercialRegister());
        s.setRestaurantImage(store.getRestaurantImage());
        storeRepository.save(s);
    }
    public void deleteStore(Integer id)
    {
        if(storeRepository.findStoreById(id) == null)
        {
//            throw new ApiException("Store not found");
        }
        storeRepository.deleteById(id);
    }

    //Find Store by Type of Acivity //Jana v2
    public List<Store> findStoreByTypeOfActivity(String typeOfActivity){
        List<Store> stores = storeRepository.findStoreByTypeOfActivity(typeOfActivity);
        if(stores.isEmpty()){
            return null;}
        return stores;
    }

    public List<Store> getBestQualityForCafesByName(String name){
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }
    public List<Store> getBestQualityForRestaurantsByName(String name){
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }
    public List<Store> getBestQualityForBothByName(String name){
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("BOTH")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }

    public List<Store> getBestQualityForCafesByDishType(String categoryName){
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus){
            stores.add(menu.getBranch().getStore());
        }
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }
    public List<Store> getBestQualityForRestaurantByDishType(String categoryName){
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus){
            stores.add(menu.getBranch().getStore());
        }
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }
    public List<Store> getBestQualityForBothByDishType(String categoryName){
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus){
            stores.add(menu.getBranch().getStore());
        }
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("BOTH")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }

    public List<Store> getBestQualityForCafesByCity(String City){
        List<Address> addresses = addressRepository.findAddressByCity(City);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());
        }
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }
    public List<Store> getBestQualityForRestaurantByCity(String City){
        List<Address> addresses = addressRepository.findAddressByCity(City);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());
        }
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }
    public List<Store> getBestQualityForBothByCity(String City){
        List<Address> addresses = addressRepository.findAddressByCity(City);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());
        }
        List<Store> chosenStores = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("BOTH")&&store.isActive()){
                chosenStores.add(store);
            }
        }
        Collections.sort(chosenStores, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageQualityStore(s2.getId()), ratingService.CalculateAverageQualityStore(s1.getId()));
            }
        });
        return chosenStores;
    }

    public List<Store> getRestaurantsYouLike(Integer clientId){
        Client client = clientRepository.findClientById(clientId);
        List<Store> stores = new ArrayList<>();
        List<Favorite> favorites = favoriteRepository.findFavoriteByClient(client);
        for (Favorite favorite : favorites) {
            if (favorite.getMenu().getBranch().getStore().getTypeOfActivity().equals("RESTAURANT")&&favorite.getMenu().getBranch().getStore().isActive()){
                stores.add(favorite.getMenu().getBranch().getStore());
            }
        }
        return stores;
    }

    public List<Store> getCafesYouLike(Integer clientId){
        Client client = clientRepository.findClientById(clientId);
        List<Store> stores = new ArrayList<>();
        List<Favorite> favorites = favoriteRepository.findFavoriteByClient(client);
        for (Favorite favorite : favorites) {
            if (favorite.getMenu().getBranch().getStore().getTypeOfActivity().equals("CAFE")&&favorite.getMenu().getBranch().getStore().isActive()){
                stores.add(favorite.getMenu().getBranch().getStore());
            }
        }
        return stores;
    }

    public List<Store> getCafesYouMayLike(Integer clientId){
        Client client = clientRepository.findClientById(clientId);
        List<Favorite> favorites = favoriteRepository.findFavoriteByClient(client);
        List<Category> categories = new ArrayList<>();
        for (Favorite favorite : favorites) {
            if (favorite.getMenu().getBranch().getStore().getTypeOfActivity().equals("CAFE")){
                categories.add(favorite.getMenu().getCategory());
            }
        }

        Map<String, Integer> categoryCount = new HashMap<>();

        for (Category category : categories) {
            String categoryName = category.getName();
            categoryCount.put(categoryName, categoryCount.getOrDefault(categoryName, 0) + 1);
        }


        String mostRepeated = null;
        int maxCount = 0;
        for (Map.Entry<String, Integer> entry : categoryCount.entrySet()) {
            if (entry.getValue() > maxCount) {
                mostRepeated = entry.getKey();
                maxCount = entry.getValue();
            }
        }
        return getBestQualityForCafesByDishType(mostRepeated);
    }

    public List<Store> getRestaurantYouMayLike(Integer clientId){
        Client client = clientRepository.findClientById(clientId);
        List<Favorite> favorites = favoriteRepository.findFavoriteByClient(client);
        List<Category> categories = new ArrayList<>();
        for (Favorite favorite : favorites) {
            if (favorite.getMenu().getBranch().getStore().getTypeOfActivity().equals("CAFE")){
                categories.add(favorite.getMenu().getCategory());
            }
        }

        Map<String, Integer> categoryCount = new HashMap<>();

        for (Category category : categories) {
            String categoryName = category.getName();
            categoryCount.put(categoryName, categoryCount.getOrDefault(categoryName, 0) + 1);
        }


        String mostRepeated = null;
        int maxCount = 0;
        for (Map.Entry<String, Integer> entry : categoryCount.entrySet()) {
            if (entry.getValue() > maxCount) {
                mostRepeated = entry.getKey();
                maxCount = entry.getValue();
            }
        }
        return getBestQualityForRestaurantByDishType(mostRepeated);
    }

    ////v3
    public List<Store> getLowestCostForCafesByName(String name) {
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")) {
                Stores1.add(store);
            }

        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));

            }

        });
        return Stores1;
    }
    ////v3
    public List<Store> getLowestCostRestaurantsByName(String name) {
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")) {
                Stores1.add(store);
            }
        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {

                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));
            }
        });
        return Stores1;
    }
    ////v3
    public List<Store> getLowestCostForBothByName(String name) {
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("BOTH")) {
                Stores1.add(store);
            }
        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {
                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));

            }
        });
        return Stores1;

    }
    ////v3
    public List<Store> getLowestCostForCafesByDishType(String categoryName) {
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus) {
            stores.add(menu.getBranch().getStore());
        }
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")) {
                Stores1.add(store);
            }
        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {
                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));
            }
        });
        return Stores1;

    }
    ////v3
    public List<Store> getLowestCostForRestaurantByDishType(String categoryName){
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus){
            stores.add(menu.getBranch().getStore());
        }
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")){
                Stores1.add(store);
            }
        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {
                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));
            }});
        return Stores1;


    }
    ////v3
    public List<Store> getLowestCostForBothByDishType(String categoryName){
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus){
            stores.add(menu.getBranch().getStore());
        }
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("BOTH")){
                Stores1.add(store);
            }
        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {
                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));

            }});
        return Stores1;
    }            ////v3
    public List<Store>  getLowestCostForCafesByCity(String City) {
        List<Address> addresses = addressRepository.findAddressByCity(City);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());
        }
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")) {
                Stores1.add(store);
            }
        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {
                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));
            }
        });
        return Stores1;
    } ////v3
    public List<Store>  getLowestCostForRestaurantByCity(String City) {
        List<Address> addresses = addressRepository.findAddressByCity(City);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());
        }
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")) {
                Stores1.add(store);
            }
        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {
                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));

            }
        });
        return Stores1;
    }       ////v3
    public List<Store> getLowestCostForBothByCity(String City){
        List<Address> addresses = addressRepository.findAddressByCity(City);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());
        }
        List<Store> Stores1 = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("BOTH")){
                Stores1.add(store);
            }
        }
        Collections.sort(Stores1, new Comparator<Store>() {
            @Override
            public int compare(Store s1, Store s2) {
                return Double.compare(ratingService.CalculateAverageCostStore(s2.getId()), ratingService.CalculateAverageCostStore(s1.getId()));

            }});
        return Stores1;






    }

    //V3 Jana
    public List<Store> getBestServiceForCafesByName(String name) {
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> cafeList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")) {
                cafeList.add(store);}}
        List<Store> sortedCafes = new ArrayList<>();
        while (!cafeList.isEmpty()) {
            Store bestStoreService = cafeList.get(0);
            for (Store store : cafeList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            sortedCafes.add(bestStoreService);
            cafeList.remove(bestStoreService);}
        return sortedCafes;}


    //V3 Jana
    public List<Store> getBestServiceForRestaurantByName(String name) {
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> restaurantList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")) {
                restaurantList.add(store);}}
        List<Store> sortedRestaurant = new ArrayList<>();
        while (!restaurantList.isEmpty()) {
            Store bestStoreService = restaurantList.get(0);
            for (Store store : restaurantList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            sortedRestaurant.add(bestStoreService);
            restaurantList.remove(bestStoreService);}
        return sortedRestaurant;}


    //V3
    public List<Store> getBestServiceForBothByName(String name) {
        List<Store> stores = storeRepository.findStoreByName(name);
        List<Store> bothStoresList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("BOTH")) {
                bothStoresList.add(store);}}
        List<Store> sortedRestaurant = new ArrayList<>();
        while (!bothStoresList.isEmpty()) {
            Store bestStoreService = bothStoresList.get(0);
            for (Store store : bothStoresList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            sortedRestaurant.add(bestStoreService);
            bothStoresList.remove(bestStoreService);}
        return sortedRestaurant;}


    //V3
    public List<Store> getBestServiceForCafesByCategoryName(String categoryName) {
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus) {
            stores.add(menu.getBranch().getStore());}
        List<Store> cafeList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")) {
                cafeList.add(store);}}
        List<Store> bestCafes = new ArrayList<>();
        while (!cafeList.isEmpty()) {
            Store bestStoreService = cafeList.get(0);
            for (Store store : cafeList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            bestCafes.add(bestStoreService);
            cafeList.remove(bestStoreService);}
        return bestCafes;
    }



    //V3
    public List<Store> getBestServiceForRestaurantByCategoryName(String categoryName) {
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus) {
            stores.add(menu.getBranch().getStore());}
        List<Store> restuarntList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")) {
                restuarntList.add(store);}}
        List<Store> bestRestaurant = new ArrayList<>();
        while (!restuarntList.isEmpty()) {
            Store bestStoreService = restuarntList.get(0);
            for (Store store : restuarntList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            bestRestaurant.add(bestStoreService);
            restuarntList.remove(bestStoreService);}
        return bestRestaurant;}


    //V3
    public List<Store> getBestServiceForBothByCategoryName(String categoryName) {
        Category category = categoryRepository.findCategoryByName(categoryName);
        List<Menu> menus = menuRepository.findMenuByCategory(category);
        List<Store> stores = new ArrayList<>();
        for (Menu menu : menus) {
            stores.add(menu.getBranch().getStore());}
        List<Store> bothList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("BOTH")) {
                bothList.add(store);}}
        List<Store> bestForBoth = new ArrayList<>();
        while (!bothList.isEmpty()) {
            Store bestStoreService = bothList.get(0);
            for (Store store : bothList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            bestForBoth.add(bestStoreService);
            bothList.remove(bestStoreService);}
        return bestForBoth;}


    //V3
    public List<Store> getBestServiceForCafeByCityName(String cityName) {
        List<Address> addresses = addressRepository.findAddressByCity(cityName);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());}
        List<Store> cafeList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("CAFE")) {
                cafeList.add(store);}}
        List<Store> bestCafe = new ArrayList<>();
        while (!cafeList.isEmpty()) {
            Store bestStoreService = cafeList.get(0);
            for (Store store : cafeList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            bestCafe.add(bestStoreService);
            cafeList.remove(bestStoreService);}
        return bestCafe;}


    //V3
    public List<Store> getBestServiceForRestaurantByCityName(String cityName) {
        List<Address> addresses = addressRepository.findAddressByCity(cityName);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());}
        List<Store> restaurantList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")) {
                restaurantList.add(store);}}
        List<Store> bestRestaurant = new ArrayList<>();
        while (!restaurantList.isEmpty()) {
            Store bestStoreService = restaurantList.get(0);
            for (Store store : restaurantList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            bestRestaurant.add(bestStoreService);
            restaurantList.remove(bestStoreService);}
        return bestRestaurant;}


    //V3
    public List<Store> getBestServiceForBothByCityName(String cityName) {
        List<Address> addresses = addressRepository.findAddressByCity(cityName);
        List<Store> stores = new ArrayList<>();
        for (Address address : addresses) {
            stores.add(address.getBranch().getStore());}
        List<Store> bothList = new ArrayList<>();
        for (Store store : stores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")) {
                bothList.add(store);}}
        List<Store> bestForBoth = new ArrayList<>();
        while (!bothList.isEmpty()) {
            Store bestStoreService = bothList.get(0);
            for (Store store : bothList) {
                if (ratingService.CalculateAverageServiceStore(store.getId()) >
                        ratingService.CalculateAverageServiceStore(bestStoreService.getId())) {
                    bestStoreService = store;}}
            bestForBoth.add(bestStoreService);
            bothList.remove(bestStoreService);}
        return bestForBoth;}

}
