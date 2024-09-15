package com.example.thawaq.Repository;

import com.example.thawaq.Model.Expert;
import com.example.thawaq.Model.Rating;
import com.example.thawaq.Model.Store;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RatingRepository extends JpaRepository<Rating, Integer> {

    Rating findRatingById(Integer id);
    ///v2
    List<Rating> findRatingByStore(Store store);
    ///v2
    List<Rating> findRatingByExpert(Expert expert);

    List<Rating> findRatingByCommentContains(String comment);
}
