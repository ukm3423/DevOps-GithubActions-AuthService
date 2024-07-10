package com.authservice.controllers;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.authservice.models.Token;
import com.authservice.repository.TokenRepository;


@RestController
@CrossOrigin
public class LogoutController {

    /**
     * * ===========================================================================
     * * ======================== Module : Logout Controller =======================
     * * ======================== Created By : Umesh Kumar =========================
     * * ======================== Created On : 04-06-2024 ==========================
     * * ===========================================================================
     * * | Code Status : On
     */

    @Autowired
    private TokenRepository tokenRepo;

    /**
     * Logout Section
     * 
     * @param jwtToken
     * @return
     */
    @PostMapping("/log-out")
    public ResponseEntity<?> postMethodName(@RequestHeader("Authorization") String jwtToken) {
        if (jwtToken != null && jwtToken.startsWith("Bearer ")) {
            jwtToken = jwtToken.substring(7);
            Token token = tokenRepo.findByToken(jwtToken).orElseThrow();
            token.setExpired(true);
            token.setRevoked(true);
            token.setUpdatedAt(LocalDateTime.now());
            tokenRepo.save(token);
        }
        return ResponseEntity.ok("Logout successful! ");
    }



}
