package com.example.thawaq.Service;

import com.example.thawaq.Api.ApiException;
import com.example.thawaq.DTO.ClientDTO;
import com.example.thawaq.DTO.ExpertDTO;
import com.example.thawaq.DTO.StoreAdminDTO;
import com.example.thawaq.Model.*;
import com.example.thawaq.Repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final StoreAdminRepository storeAdminRepository;
    private final ExpertRepository expertRepository;
    private final StoreRepository storeRepository;

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserById(Integer id) {
        return userRepository.findUserById(id);
    }

    public void clientRegister(ClientDTO clientDTO) {
        String hash = new BCryptPasswordEncoder().encode(clientDTO.getPassword());
        User user = new User(null, clientDTO.getUsername(), hash, "CLIENT" , clientDTO.getFirstName(), clientDTO.getLastName(), clientDTO.getEmail(), clientDTO.getPhoneNumber(), clientDTO.getCountry(), clientDTO.getCity(), null,null,null);
        userRepository.save(user);
        Client client = new Client (null , user , null,null);
        clientRepository.save(client);
    }
    public void storeAdminRegister(StoreAdminDTO storeAdminDTO) {
        String hash = new BCryptPasswordEncoder().encode(storeAdminDTO.getPassword());
        User user = new User(null,storeAdminDTO.getUsername(),hash,"STORE",storeAdminDTO.getFirstName(),storeAdminDTO.getLastName(),storeAdminDTO.getEmail(),storeAdminDTO.getPhoneNumber(), storeAdminDTO.getCountry(), storeAdminDTO.getCity(), null,null,null);
        userRepository.save(user);
        StoreAdmin storeAdmin = new StoreAdmin(null , user,false,null);
        storeAdminRepository.save(storeAdmin);
    }

    public void expertRegister(ExpertDTO expertDTO) {
        String hash = new BCryptPasswordEncoder().encode(expertDTO.getPassword());
        User user = new User(null, expertDTO.getUsername(), hash, "EXPERT" , expertDTO.getFirstName(), expertDTO.getLastName(), expertDTO.getEmail(), expertDTO.getPhoneNumber(), expertDTO.getCountry(), expertDTO.getCity(), null,null,null);
        userRepository.save(user);
        Expert expert = new Expert(null, expertDTO.getBrief(), expertDTO.getInstagram(), expertDTO.getX(), false , user,null,null);
        expertRepository.save(expert);
    }

    public void clientUpdate(ClientDTO clientDTO) {
        User user = userRepository.findUserById(clientDTO.getId());
        if (user == null) {
            throw new ApiException("User not found");
        }
        user.setUsername(clientDTO.getUsername());
        user.setPassword(clientDTO.getPassword());
        user.setFirstName(clientDTO.getFirstName());
        user.setLastName(clientDTO.getLastName());
        user.setEmail(clientDTO.getEmail());
        user.setPhoneNumber(clientDTO.getPhoneNumber());
        user.setCountry(clientDTO.getCountry());
        user.setCity(clientDTO.getCity());
        userRepository.save(user);
    }

    public void storeAdminUpdate(StoreAdminDTO storeAdminDTO) {
        User user = userRepository.findUserById(storeAdminDTO.getId());
        if (user == null) {
            throw new ApiException("User not found");
        }
        user.setUsername(storeAdminDTO.getUsername());
        user.setPassword(storeAdminDTO.getPassword());
        user.setFirstName(storeAdminDTO.getFirstName());
        user.setLastName(storeAdminDTO.getLastName());
        user.setEmail(storeAdminDTO.getEmail());
        user.setPhoneNumber(storeAdminDTO.getPhoneNumber());
        user.setCountry(storeAdminDTO.getCountry());
        user.setCity(storeAdminDTO.getCity());
        userRepository.save(user);
    }

    public void expertUpdate(ExpertDTO expertDTO){
        User user = userRepository.findUserById(expertDTO.getId());
        if (user == null) {
            throw new ApiException("User not found");
        }
        Expert expert = expertRepository.findExpertById(expertDTO.getId());
        user.setUsername(expertDTO.getUsername());
        user.setPassword(expertDTO.getPassword());
        user.setFirstName(expertDTO.getFirstName());
        user.setLastName(expertDTO.getLastName());
        user.setEmail(expertDTO.getEmail());
        user.setPhoneNumber(expertDTO.getPhoneNumber());
        user.setCountry(expertDTO.getCountry());
        user.setCity(expertDTO.getCity());
        userRepository.save(user);
        expert.setBrief(expertDTO.getBrief());
        expert.setInstagram(expertDTO.getInstagram());
        expert.setX(expertDTO.getX());
        expertRepository.save(expert);
    }

    public void deleteUserById(Integer id) {
        userRepository.deleteById(id);
    }

    ///v2
    public void BlockExpert(Integer  expertId,Integer userId) {
        Expert expert = expertRepository.findExpertById(expertId);
        User user = userRepository.findUserById(userId);
        if (!user.getRole().equals("ADMIN"))
            throw new ApiException("You are not allowed to block this expert");

        if (expert == null||user==null) {
            throw new ApiException("Expert not found or storeAdmin not found");
        }
        expert.setActive(false);
        expertRepository.save(expert);


    }
    ///v2
    public void UnblockExpert(Integer  expertId,Integer userId) {
        Expert expert = expertRepository.findExpertById(expertId);
        User user = userRepository.findUserById(userId);
        if (!user.getRole().equals("ADMIN"))
            throw new ApiException("You are not allowed to block this expert");

        if (expert == null||user==null) {
            throw new ApiException("Expert not found or storeAdmin not found");
        }
        expert.setActive(true);
        expertRepository.save(expert);

    }
    ///v2
    public void BlockStoreAdmin(Integer storeAdminId,Integer userId) {
        StoreAdmin storeAdmin = storeAdminRepository.findStoreAdminById(storeAdminId);
        User user = userRepository.findUserById(userId);

        if (!user.getRole().equals("ADMIN"))
            throw new ApiException("You are not allowed to block this storeAdmin");

        if (storeAdmin == null||user==null) {
            throw new ApiException("Store admin not found or storeAdmin not found");
        }
        storeAdmin.setActive(false);
        storeAdminRepository.save(storeAdmin);


    }
    ///v2
    public void UnBlockStoreAdmin(Integer storeAdminId,Integer userId) {
        StoreAdmin storeAdmin = storeAdminRepository.findStoreAdminById(storeAdminId);
        User user = userRepository.findUserById(userId);

        if (!user.getRole().equals("ADMIN"))
            throw new ApiException("You are not allowed to unblock this storeAdmin");


        if (storeAdmin == null || user == null) {
            throw new ApiException("Store admin not found or storeAdmin not found");

        }
        storeAdmin.setActive(true);
        storeAdminRepository.save(storeAdmin);

    }

    public void blockStore(Integer storeId,Integer userId) {
        Store store = storeRepository.findStoreById(storeId);
        User user = userRepository.findUserById(userId);
        if (!user.getRole().equals("ADMIN"))
            throw new ApiException("You are not allowed to block this storeAdmin");

        if (store == null||user==null) {
            throw new ApiException("Store admin not found or storeAdmin not found");
        }
        store.setActive(false);
        storeRepository.save(store);
    }

    public void unBlockStore(Integer storeId,Integer userId) {
        Store store = storeRepository.findStoreById(storeId);
        User user = userRepository.findUserById(userId);
        if (store == null||user==null) {
            throw new ApiException("Store admin not found or storeAdmin not found");
        }
        store.setActive(true);
        storeRepository.save(store);
    }

    //V3
    public void activateStoreAdmin(Integer storeAdminId) {
        StoreAdmin storeAdmin = storeAdminRepository.findStoreAdminById(storeAdminId);
        if (storeAdmin == null) {
            throw new ApiException("Store Admin not found");}
        storeAdmin.setActive(true);
        storeAdminRepository.save(storeAdmin);}

    //V3
    public void DeactivateStoreAdmin(Integer storeAdminId) {
        StoreAdmin storeAdmin = storeAdminRepository.findStoreAdminById(storeAdminId);
        if (storeAdmin == null) {
            throw new ApiException("Store Admin not found");}
        storeAdmin.setActive(false);
        storeAdminRepository.save(storeAdmin);}
}



