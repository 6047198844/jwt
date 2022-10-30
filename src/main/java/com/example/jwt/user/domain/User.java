package com.example.jwt.user.domain;

import com.example.jwt.user.domain.constant.UserRole;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.logging.log4j.util.Strings;

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
    @Setter
    private String refreshToken;
    private Boolean enabled;

    public void addRoles(UserRole userRole) {
        if (Strings.isEmpty(roles)) {
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

    public void updateRefreshToken(String newToken) {
        this.refreshToken = newToken;
    }

    public boolean isEnabled() {
        return true;
    }

    public void giveUserPermission() {
        this.addRoles(UserRole.ROLE_USER);
    }
}