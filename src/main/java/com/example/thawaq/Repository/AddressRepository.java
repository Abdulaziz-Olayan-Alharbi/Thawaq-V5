package com.example.thawaq.Repository;

import com.example.thawaq.Model.Address;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AddressRepository extends JpaRepository<Address,Integer> {

    Address findAddressById(Integer id);
    List<Address> findAddressByCity(String city);
}
