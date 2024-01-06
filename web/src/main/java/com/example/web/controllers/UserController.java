package com.example.web.controllers;

import com.example.web.auth.AuthenticationService;
import com.example.web.auth.VerificationTokenResult;
import com.example.web.exceptions.ErrorResponse;
import com.example.web.exceptions.SuccessResponse;
import com.example.web.mapstruct.AuthenticationRequest;
import com.example.web.mapstruct.UsersDto;
import com.example.web.model.User;
import com.example.web.model.VerificationToken;
import com.example.web.repository.UserRepository;
import com.example.web.responses.AuthenticationResponse;
import com.example.web.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class UserController {

    private final AuthenticationService service;
    private final UserRepository repository;

    @Autowired
    public UserController(AuthenticationService service, UserRepository repository) {
        this.service = service;
        this.repository = repository;
    }

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody UsersDto request){
        // Check if email already exists
        if (emailExists(request.getEmail())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse("Sorry..! Email already been used by a user.", "409"));
        }
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        try {
            AuthenticationResponse response = service.authenticate(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Invalid email or password", "401"));
        }
    }

    // Helper method to check if email already exists
    private boolean emailExists(String email) {
        Optional<User> existingUsers =  repository.findByEmail(email);
        return existingUsers.isPresent();
    }

    @GetMapping("/verifyRegistration")
    public ResponseEntity<Object> verifyRegistration(@RequestParam("token") String token) {
        String result=service.verifyUser(token);
        if (result.equalsIgnoreCase("valid")){
            return ResponseEntity.ok("User registration verified successfully");
        } else if (result.equalsIgnoreCase("expired")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("Verification token has expired, Click the resend button to have a new token assign to you.", "400"));
        } else{
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("Invalid verification token", "400"));
        }
    }

    @GetMapping("/resendVerifyToken")
    public ResponseEntity<Object> resendVerificationToken(@RequestParam("token") String OldToken, HttpServletRequest request) {
        VerificationTokenResult result = service.generateNewVerificationToken(OldToken);
        if (result.isSuccess()) {
            VerificationToken verificationToken = (VerificationToken) result.getData();
            Long user = verificationToken.getId();
            service.resendVerificationTokenMail(user, verificationToken);
            return ResponseEntity.ok("We have resent the verification link to your email.");
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(result.getData());
        }
    }
}
