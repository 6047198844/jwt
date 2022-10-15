package com.example.jwt.user.domain;

import com.example.jwt.user.domain.constant.UserRole;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Builder
@ToString
public class User {
    private String username;
    private String password;
    private String email;
    @Builder.Default
    private String roles = "";

    public void addRoles(UserRole userRole) {
        if (roles.isEmpty()) {
            roles = userRole.name();
        }
        roles += String.format(",%s",userRole);
    }

    public List<UserRole> getRoles() {
        if(this.roles.length() > 0){
            return Arrays.stream(this.roles.split(","))
                    .map(UserRole::valueOf)
                    .collect(Collectors.toList());
        }
        return new ArrayList<>();
    }

    public void setPassword(String password) {
        this.password = password;
    }
}