package com.example.thawaq.Repository;

import com.example.thawaq.Model.Client;
import com.example.thawaq.Model.Favorite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FavoriteRepository extends JpaRepository<Favorite, Integer> {
    Favorite findFavoriteById(Integer id);
    List<Favorite> findFavoriteByClient(Client client);
}
