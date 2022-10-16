package com.example.jwt.user.application;

import com.example.jwt.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserCommonService {
    private final UserRepository userRepository;
    public Optional<User> findByUserName(final String username) {
        return userRepository.findByUsername(username);
    }
}