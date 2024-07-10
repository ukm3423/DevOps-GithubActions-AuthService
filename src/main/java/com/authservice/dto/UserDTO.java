package com.authservice.dto;

import com.authservice.models.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDTO {

    private String fullname;

    private String email;

    private String password;

    private Long phoneNo;

    private Role role;

}
