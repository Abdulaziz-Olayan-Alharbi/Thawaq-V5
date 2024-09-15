package com.example.thawaq.Repository;

import com.example.thawaq.Model.Expert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ExpertRepository extends JpaRepository<Expert, Integer> {
    Expert findExpertById(Integer id);
    @Query("SELECT e FROM Expert e JOIN e.ratings r GROUP BY e ORDER BY SUM(r.averageRating) DESC")
    List<Expert> findExpertsByTotalRating();
}
