package com.example.thawaq.Service;


import com.example.thawaq.Api.ApiException;
import com.example.thawaq.Model.Client;
import com.example.thawaq.Model.Favorite;
import com.example.thawaq.Model.Menu;
import com.example.thawaq.Repository.ClientRepository;
import com.example.thawaq.Repository.FavoriteRepository;
import com.example.thawaq.Repository.MenuRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@AllArgsConstructor
public class FavoriteService {
    private final FavoriteRepository favoriteRepository;
    private final MenuRepository menuRepository;
    private final ClientRepository clientRepository;

    public List<Favorite> get() {
        return favoriteRepository.findAll();
    }

    public void AddFavorite(Integer MenuId , Integer clientId) {
        Client client = clientRepository.findClientById(clientId);
        if (client == null) {
            throw new ApiException("Client not found");
        }
        Menu menu = menuRepository.findMenuById(MenuId);
        if (menu==null){
            throw new ApiException("can not add favorite");
        }
        Favorite favorite = new Favorite();
        favorite.setMenu(menu);
        favorite.setClient(client);
        favoriteRepository.save(favorite);
    }

    public void DeleteFavorite(Integer favoriteId) {
        Favorite favorite = favoriteRepository.findFavoriteById(favoriteId);
        if (favorite ==null){
            throw new ApiException("can not delete favorite");
        }
        favoriteRepository.delete(favorite);

    }


}
