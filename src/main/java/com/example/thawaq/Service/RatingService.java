package com.example.thawaq.Service;

import com.example.thawaq.Api.ApiException;
import com.example.thawaq.Model.*;
import com.example.thawaq.Repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor

public class RatingService {
    private final RatingRepository ratingRepository;
    private final ExpertRepository expertRepository;
    private final StoreRepository storeRepository;
    private final UserRepository userRepository;
    private final MenuRepository menuRepository;
    private final ClientRepository clientRepository;

    public List<Rating> getAllRatings() {
        return ratingRepository.findAll();
    }

    //Add rating from the user to the store  v3
    public void addRatingFromUserToStore(Rating rating,Integer userId, Integer storeId) {
        Client c  = clientRepository.findClientById(userId);
        Store s = storeRepository.findStoreById(storeId);
        if(c==null) {
            throw new ApiException("User not found");}
        if(s==null) {
            throw new ApiException("Store not found");}
        if(!s.isActive()){
            throw new ApiException("Store is not active");}
        rating.setStore(s);
        rating.setClient(c);
        double avr = (rating.getCleaning()+rating.getCost()+rating.getQuality()+rating.getService()) / 4;
        rating.setAverageRating(avr);
        ratingRepository.save(rating);}

    //Add rating from expert to the store  v3
    public void addRatingFromExpertToStore(Rating rating,Integer expertId, Integer storeId) {
        Expert e =expertRepository.findExpertById(expertId);
        Store s = storeRepository.findStoreById(storeId);
        if(e==null) {
            throw new ApiException("User not found");}
        if(s==null) {
            throw new ApiException("Store not found");}
        if(!e.isActive()){
            throw new ApiException("Expert is not active");}
        if(!s.isActive()){
            throw new ApiException("Store is not active");}
        rating.setStore(s);
        rating.setExpert(e);
        double avr = (rating.getCleaning()+rating.getCost()+rating.getQuality()+rating.getService()) / 4;
        rating.setAverageRating(avr);
        ratingRepository.save(rating);}



    public void updateRating(Rating rating,Integer id) {
        Rating r = ratingRepository.findRatingById(id);
        if(r == null) {
            throw new ApiException("Rating not found");}
        r.setService(rating.getService());
        r.setCleaning(rating.getCleaning());
        r.setQuality(rating.getQuality());
        r.setCost(rating.getCost());
        r.setComment(rating.getComment());
        r.setTitle(rating.getTitle());
        r.setAverageRating(rating.getAverageRating());
        ratingRepository.save(r);}



    public void deleteRating(Integer id) {
        Rating r = ratingRepository.findRatingById(id);
        if(r == null) {
            throw new ApiException("Rating not found");}
        ratingRepository.delete(r);
    }

    ///v2

    public double CalculateAverageRatingExpert(Integer expertId) {
        Expert expert = expertRepository.findExpertById(expertId);
        if (expert == null) {
            throw new ApiException("Expert not found");
        }

        List<Rating> ratings = ratingRepository.findRatingByExpert(expert);
        if (ratings.isEmpty()) {
            throw new ApiException("No ratings found for the given expert");
        }


        double total = 0;
        for (Rating rating : ratings) {
            total += rating.getAverageRating();
        }

        return total / ratings.size();
    }
    public double CalculateAverageStore(Integer storeId) {
        Store store =storeRepository.findStoreById(storeId);
        if (store == null) {
            throw new ApiException("store not found");
        }

        List<Rating> ratings = ratingRepository.findRatingByStore(store);
        if (ratings.isEmpty()) {
            throw new ApiException("No ratings found for the given store");
        }


        double total = 0;
        for (Rating rating : ratings) {
            total += rating.getAverageRating();
        }

        return total / ratings.size();
    }
    ///v2
    public double CalculateAverageQualityStore(Integer storeId) {
        Store store =storeRepository.findStoreById(storeId);
        if (store == null) {
            throw new ApiException("store not found");
        }

        List<Rating> ratings = ratingRepository.findRatingByStore(store);
        if (ratings.isEmpty()) {
            throw new ApiException("No ratings found for the given store");
        }


        double total = 0;
        for (Rating rating : ratings) {
            total += rating.getQuality();
        }

        return total / ratings.size();
    }

    public List<Store> getBOTHByCleaningOfRating()  //v2
    {
        List<Store> s = storeRepository.findStoreByTypeOfActivity("BOTH");
        if(s.isEmpty())
        {
            throw new ApiException("Store (BOTH) is empty");
        }
//        if(s.size() == 1)
//        {
//            return s;
//        }
        int count;
        double d ;
        List<Rating> r = ratingRepository.findAll();
        Double[] aaSum = new Double[s.size()];
        Integer[] aaID = new Integer[s.size()];
        for (int i = 0; i < s.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r.get(j).getStore().getId() == s.get(i).getId())
                {
                    d += r.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s.get(i).getId();
            }
        }

        for (int i = 0; i < s.size(); i++) {
            for (int j = i; j < s.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }
//        count = 0;
//        List<Store> ss2 = storeRepository.findAll();
        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }

//        for (int i = 0; i < storeRepository.findAll().size(); i++) {
//            if(ss2.get(i).getId() == aaID[count])
//            {
//                sss2.add(ss2.get(i));
//                sss2.addAll(ss2);
//                count++;
//            }
//        }
        return sss2;
    }

    public List<Store> getRestaurantByCleaningOfRating()  //v2
    {
        List<Store> s = storeRepository.findStoreByTypeOfActivity("RESTAURANT");
        if(s.isEmpty())
        {
            throw new ApiException("Store (RESTAURANT) is empty");
        }
//        if(s.size() == 1)
//        {
//            return s;
//        }
        int count;
        double d ;
        List<Rating> r = ratingRepository.findAll();
        Double[] aaSum = new Double[s.size()];
        Integer[] aaID = new Integer[s.size()];
        for (int i = 0; i < s.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r.get(j).getStore().getId() == s.get(i).getId())
                {
                    d += r.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s.get(i).getId();
            }
        }

        for (int i = 0; i < s.size(); i++) {
            for (int j = i; j < s.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }
//        count = 0;
//        List<Store> ss2 = storeRepository.findAll();
        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }

//        for (int i = 0; i < storeRepository.findAll().size(); i++) {
//            if(ss2.get(i).getId() == aaID[count])
//            {
//                sss2.add(ss2.get(i));
//                sss2.addAll(ss2);
//                count++;
//            }
//        }
        return sss2;
    }
    public List<Store> getCafeByCleaningOfRating()  //v2
    {
        List<Store> s2 = storeRepository.findStoreByTypeOfActivity("CAFE");
        if(s2.isEmpty())
        {
            throw new ApiException("Store (CAFE) is empty");
        }
//        if(s2.size() == 1)
//        {
//            return s2;
//        }
        int count;
        double d ;
        List<Rating> r2 = ratingRepository.findAll();
        Double[] aaSum = new Double[s2.size()];
        Integer[] aaID = new Integer[s2.size()];
        for (int i = 0; i < s2.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r2.get(j).getStore().getId() == s2.get(i).getId())
                {
                    d += r2.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s2.get(i).getId();
            }
        }

        for (int i = 0; i < s2.size(); i++) {
            for (int j = i; j < s2.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }
//        count = 0;
//        List<Store> ss2 = storeRepository.findAll();
        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }

//        for (int i = 0; i < storeRepository.findAll().size(); i++) {
//            if(ss2.get(i).getId() == aaID[count])
//            {
//                sss2.add(ss2.get(i));
//                sss2.addAll(ss2);
//                count++;
//            }
//        }
        return sss2;
    }

    public Set<Branch> getBranchBOTHByCleaningOfRating()  //v2
    {
        List<Store> s2 = storeRepository.findStoreByTypeOfActivity("BOTH");
        if(s2.isEmpty())
        {
            throw new ApiException("Store (BOTH) is empty");
        }
        Set<Branch> branchSet = new HashSet<>();
//        if(s2.size() == 1)
//        {
//            branchSet.addAll(s2.get(0).getBranches());
//            return branchSet;
//        }
        int count;
        double d ;
        List<Rating> r2 = ratingRepository.findAll();
        Double[] aaSum = new Double[s2.size()];
        Integer[] aaID = new Integer[s2.size()];
        for (int i = 0; i < s2.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r2.get(j).getStore().getId() == s2.get(i).getId())
                {
                    d += r2.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s2.get(i).getId();
            }
        }
        for (int i = 0; i < s2.size(); i++) {
            for (int j = i; j < s2.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }

        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }
        for (int i = 0; i < sss2.size(); i++) {
            branchSet.addAll(sss2.get(i).getBranches());
        }
        if(branchSet.isEmpty())
        {
            throw new ApiException("branchSet not found");
        }
        return branchSet;

//        List<Store> sss2 = new ArrayList<>();
//        for (int i = 0; i < aaID.length; i++) {
//            sss2.add(storeRepository.findStoreById(aaID[i]));
//        }
//        int wq = 0;
////        List<Branch> branchList2 = branchRepository.findAll();
//        for (int i = 0; i < sss2.size(); i++) {
//            for (int j = 0; j < branchRepository.findAll().size(); j++) {
//                if(sss2.get(i).getId() == branchRepository.findAll().get(j).getStore().getId())
//                {
//                    wq++;
////                    branchSet.add(branchRepository.findBranchById(branchRepository.findAll().get(j).getStore().getId()));
//                }
//            }
//        }
//        count = 0;
//        Integer[] bbID = new Integer[wq];
//        for (int i = 0; i < sss2.size(); i++) {
//            for (int j = 0; j < branchRepository.findAll().size(); j++) {
//                if(sss2.get(i).getId() == branchRepository.findAll().get(j).getStore().getId())
//                {
//                    bbID[count] = branchRepository.findAll().get(j).getStore().getId();
//                    count++;
//                }
//            }
//        }
//        for (int i = 0; i < bbID.length; i++) {
////            sss2.add(storeRepository.findStoreById(aaID[i]));
//            branchSet.add(branchRepository.findBranchById(bbID[i]));
//        }
////        for (int i = 0; i < sss2.size(); i++) {
////            branchSet.addAll(sss2.get(i).getBranches());
////        }
//        if(branchSet.isEmpty())
//        {
//            throw new ApiException("branchSet not found");
//        }
//        return branchSet;
    }
    public Set<Branch> getBranchRestaurantByCleaningOfRating()  //v2
    {
        List<Store> s2 = storeRepository.findStoreByTypeOfActivity("RESTAURANT");
        if(s2.isEmpty())
        {
            throw new ApiException("Store (BOTH) is empty");
        }
        Set<Branch> branchSet = new HashSet<>();
//        if(s2.size() == 1)
//        {
//            branchSet.addAll(s2.get(0).getBranches());
//            return branchSet;
//        }
        int count;
        double d ;
        List<Rating> r2 = ratingRepository.findAll();
        Double[] aaSum = new Double[s2.size()];
        Integer[] aaID = new Integer[s2.size()];
        for (int i = 0; i < s2.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r2.get(j).getStore().getId() == s2.get(i).getId())
                {
                    d += r2.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s2.get(i).getId();
            }
        }
        for (int i = 0; i < s2.size(); i++) {
            for (int j = i; j < s2.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }
        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }
        for (int i = 0; i < sss2.size(); i++) {
            branchSet.addAll(sss2.get(i).getBranches());
        }
        if(branchSet.isEmpty())
        {
            throw new ApiException("branchSet not found");
        }
        return branchSet;
    }
    public Set<Branch> getBranchCafeByCleaningOfRating()  //v2
    {
        List<Store> s2 = storeRepository.findStoreByTypeOfActivity("CAFE");
        if(s2.isEmpty())
        {
            throw new ApiException("Store (CAFE) is empty");
        }
        Set<Branch> branchSet = new HashSet<>();
//        if(s2.size() == 1)
//        {
//            branchSet.addAll(s2.get(0).getBranches());
//            return branchSet;
//        }
        int count;
        double d ;
        List<Rating> r2 = ratingRepository.findAll();
        Double[] aaSum = new Double[s2.size()];
        Integer[] aaID = new Integer[s2.size()];
        for (int i = 0; i < s2.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r2.get(j).getStore().getId() == s2.get(i).getId())
                {
                    d += r2.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s2.get(i).getId();
            }
        }
        for (int i = 0; i < s2.size(); i++) {
            for (int j = i; j < s2.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }
        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }
        for (int i = 0; i < sss2.size(); i++) {
            branchSet.addAll(sss2.get(i).getBranches());
        }
        if(branchSet.isEmpty())
        {
            throw new ApiException("branchSet not found");
        }
        return branchSet;
    }

    public List<Rating> getRatingByLatest()  //v2
    {
        List<Rating> list = new ArrayList<>();

        for (int i = ratingRepository.findAll().size()-1; i >= 0; i--) {
            Rating temp;
            list.add(ratingRepository.findAll().get(i));
        }

        return list;
    }
    public List<Rating> getRatingByHigh()  //v2
    {
        List<Rating> list = ratingRepository.findAll();
        for (int i = 0; i < ratingRepository.findAll().size(); i++) {
            list.get(i).setAverageRating((list.get(i).getService()+list.get(i).getCost()+list.get(i).getQuality()+list.get(i).getCleaning())/4);
        }
        for (int i = 0; i < list.size(); i++) {
            for (int j = i; j < list.size(); j++) {
                if(list.get(i).getAverageRating() < list.get(j).getAverageRating())
                {
                    Rating temp = list.get(i);
                    list.set(i,list.get(j));
                    list.set(j,temp);
                }
            }
        }
        return list;
    }
    public List<Rating> getRatingByLow()  //v2
    {
        List<Rating> list = ratingRepository.findAll();
        for (int i = 0; i < ratingRepository.findAll().size(); i++) {
            list.get(i).setAverageRating((list.get(i).getService()+list.get(i).getCost()+list.get(i).getQuality()+list.get(i).getCleaning())/4);
        }
        for (int i = 0; i < list.size(); i++) {
            for (int j = i; j < list.size(); j++) {
                if(list.get(i).getAverageRating() > list.get(j).getAverageRating())
                {
                    Rating temp = list.get(i);
                    list.set(i,list.get(j));
                    list.set(j,temp);
                }
            }
        }
        return list;
    }
    public List<Rating> getRatingByComment(String comment)  //v2
    {
        if(ratingRepository.findRatingByCommentContains(comment).isEmpty())
        {
            throw new ApiException("Rating not found");
        }
        return ratingRepository.findRatingByCommentContains(comment);
    }

    ////v3
    public double CalculateAverageCostStore(Integer storeId) {
        Store store =storeRepository.findStoreById(storeId);
        if (store == null) {
            throw new ApiException("store not found");
        }

        List<Rating> ratings = ratingRepository.findRatingByStore(store);
        if (ratings.isEmpty()) {
            throw new ApiException("No ratings found for the given store");
        }


        double total = 0;
        for (Rating rating : ratings) {
            total += rating.getCost();
        }
        return total / ratings.size();


    }



    public double CalculateAverageServiceStore(Integer storeId) {
        Store store =storeRepository.findStoreById(storeId);
        if (store == null) {
            throw new ApiException("Store not found");
        }
        List<Rating> ratings = ratingRepository.findRatingByStore(store);
        if (ratings.isEmpty()) {
            throw new ApiException("No ratings found for the given store");
        }
        double total = 0;
        for (Rating rating : ratings) {
            total += rating.getService();}
        return total / ratings.size();
    }


    //V3
    public List<Store> getTop4CafesByAverageRating() {
        List<Store> allStores = storeRepository.findAll();
        List<Store> cafeList = new ArrayList<>();
        for (Store store : allStores) {
            if (store.getTypeOfActivity().equals("CAFE")) {
                cafeList.add(store);
            }}
        List<Store> bestTop4Cafes = new ArrayList<>();
        while (bestTop4Cafes.size() < 4 && !cafeList.isEmpty()) {
            Store bestCafe = cafeList.get(0);
            for (Store store : cafeList) {
                if (CalculateAverageStore(store.getId()) > CalculateAverageStore(bestCafe.getId())) {
                    bestCafe = store;}}
            bestTop4Cafes.add(bestCafe);
            cafeList.remove(bestCafe);}
        return bestTop4Cafes;}


    //V3
    public List<Store> getTop4RestaurantByAverageRating() {
        List<Store> allStores = storeRepository.findAll();
        List<Store> restaurantList = new ArrayList<>();
        for (Store store : allStores) {
            if (store.getTypeOfActivity().equals("RESTAURANT")) {
                restaurantList.add(store);
            }}
        List<Store> bestTop4Restaurant = new ArrayList<>();
        while (bestTop4Restaurant.size() < 4 && !restaurantList.isEmpty()) {
            Store bestRestaurant = restaurantList.get(0);
            for (Store store : restaurantList) {
                if (CalculateAverageStore(store.getId()) > CalculateAverageStore(bestRestaurant.getId())) {
                    bestRestaurant = store;}}
            bestTop4Restaurant.add(bestRestaurant);
            restaurantList.remove(bestRestaurant);}
        return bestTop4Restaurant;}


    public List<Menu> getMenuBOTHByCleaningOfRating()  //v2
    {
        List<Store> s2 = storeRepository.findStoreByTypeOfActivity("BOTH");
        if(s2.isEmpty())
        {
            throw new ApiException("Store (BOTH) is empty");
        }
        Set<Branch> branchSet = new HashSet<>();
        List<Menu> menuList = new ArrayList<>();
//        if(s2.get(0).getBranches().size() == 1)
//        {
//            branchSet.addAll(s2.get(0).getBranches());
//            menuSet.addAll(menuRepository.findAll());
//            return menuSet;
//        }
        int count;
        double d ;
        List<Rating> r2 = ratingRepository.findAll();
        Double[] aaSum = new Double[s2.size()];
        Integer[] aaID = new Integer[s2.size()];
        for (int i = 0; i < s2.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r2.get(j).getStore().getId() == s2.get(i).getId())
                {
                    d += r2.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s2.get(i).getId();
            }
        }
        for (int i = 0; i < s2.size(); i++) {
            for (int j = i; j < s2.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }
        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }
        for (int i = 0; i < sss2.size(); i++) {
            branchSet.addAll(sss2.get(i).getBranches());
        }
        if(branchSet.isEmpty())
        {
            throw new ApiException("branchSet not found");
        }
        for (int i = 0; i < branchSet.size(); i++) {
            menuList.addAll(branchSet.stream().toList().get(i).getMenus());
        }
        if(menuList.isEmpty())
        {
            throw new ApiException("MenuSet not found");
        }
        return menuList;
    }
    public List<Menu> getMenuRestaurantByCleaningOfRating()  //v2
    {
        List<Store> s2 = storeRepository.findStoreByTypeOfActivity("RESTAURANT");
        if(s2.isEmpty())
        {
            throw new ApiException("Store (RESTAURANT) is empty");
        }
        Set<Branch> branchSet = new HashSet<>();
        List<Menu> menuList = new ArrayList<>();
//        if(s2.get(0).getBranches().size() == 1)
//        {
//            branchSet.addAll(s2.get(0).getBranches());
//            menuSet.addAll(menuRepository.findAll());
//            return menuSet;
//        }
        int count;
        double d ;
        List<Rating> r2 = ratingRepository.findAll();
        Double[] aaSum = new Double[s2.size()];
        Integer[] aaID = new Integer[s2.size()];
        for (int i = 0; i < s2.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r2.get(j).getStore().getId() == s2.get(i).getId())
                {
                    d += r2.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s2.get(i).getId();
            }
        }
        for (int i = 0; i < s2.size(); i++) {
            for (int j = i; j < s2.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }
        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }
        for (int i = 0; i < sss2.size(); i++) {
            branchSet.addAll(sss2.get(i).getBranches());
        }
        for (int i = 0; i < branchSet.size(); i++) {
            menuList.addAll(branchSet.stream().toList().get(i).getMenus());
        }
        if(branchSet.isEmpty())
        {
            throw new ApiException("branchSet not found");
        }
        if(menuList.isEmpty())
        {
            throw new ApiException("MenuSet not found");
        }
        return menuList;
    }
    public List<Menu> getMenuCafeByCleaningOfRating()  //v2
    {
        List<Store> s2 = storeRepository.findStoreByTypeOfActivity("CAFE");
        if(s2.isEmpty())
        {
            throw new ApiException("Store (CAFE) is empty");
        }
        Set<Branch> branchSet = new HashSet<>();
        List<Menu> menuList = new ArrayList<>();
//        if(s2.get(0).getBranches().size() == 1)
//        {
//            branchSet.addAll(s2.get(0).getBranches());
//            menuList.addAll(menuRepository.findAll());
//            return menuList;
//        }
        int count;
        double d ;
        List<Rating> r2 = ratingRepository.findAll();
        Double[] aaSum = new Double[s2.size()];
        Integer[] aaID = new Integer[s2.size()];
        for (int i = 0; i < s2.size(); i++) {
            count = 0;
            d = 0;
            for (int j = 0; j < ratingRepository.findAll().size(); j++) {
                if(r2.get(j).getStore().getId() == s2.get(i).getId())
                {
                    d += r2.get(j).getCleaning();
                    count++;
                }
                aaSum[i] = d/count;
                aaID[i] = s2.get(i).getId();
            }
        }
        for (int i = 0; i < s2.size(); i++) {
            for (int j = i; j < s2.size(); j++) {
                if(aaSum[i] <= aaSum[j])
                {
                    double temp1 = aaSum[i];
                    aaSum[i] = aaSum[j];
                    aaSum[j] = temp1;

                    int temp2 = aaID[i];
                    aaID[i] = aaID[j];
                    aaID[j] = temp2;
                }
            }
        }
        List<Store> sss2 = new ArrayList<>();
        for (int i = 0; i < aaID.length; i++) {
            sss2.add(storeRepository.findStoreById(aaID[i]));
        }
        for (int i = 0; i < sss2.size(); i++) {
            branchSet.addAll(sss2.get(i).getBranches());
        }
        for (int i = 0; i < branchSet.size(); i++) {
            menuList.addAll(branchSet.stream().toList().get(i).getMenus());
        }
        if(branchSet.isEmpty())
        {
            throw new ApiException("branchSet not found");
        }
        if(menuList.isEmpty())
        {
            throw new ApiException("MenuSet not found");
        }
        return menuList;
    }

}
