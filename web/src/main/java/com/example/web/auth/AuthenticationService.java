package com.example.web.auth;

import com.example.web.config.JwtService;
import com.example.web.mapstruct.UsersDto;
import com.example.web.model.Role;
import com.example.web.model.User;
import com.example.web.model.VerificationToken;
import com.example.web.repository.UserRepository;
import com.example.web.mapstruct.AuthenticationRequest;
import com.example.web.repository.VerificationTokenRepository;
import com.example.web.responses.AuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final VerificationTokenRepository verificationTokenRepository;
    private static final int EXPIRATION_MINUTES = 10;
    @Autowired
    private HttpServletRequest request;
    private Date expirationTime;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    public AuthenticationResponse register(UsersDto request) {
        Long nextUserId = getNextUserId();
        logger.info(String.valueOf(nextUserId));
        var user = User.builder()
                .id(nextUserId)
                .name(request.getName())
                .email(request.getEmail())
                .address(request.getAddress())
                .photoUrl(request.getPhotoUrl())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        user.setId(nextUserId);
        repository.save(user);
        // Create a verification token
        UUID verificationToken = UUID.randomUUID();
        expirationTime = calculateExpirationDate(EXPIRATION_MINUTES);
        VerificationToken tokenEntity = VerificationToken.builder()
                .token(String.valueOf(verificationToken))
                .id(nextUserId)
                .expirationTime(expirationTime)
                .build();
        verificationTokenRepository.save(tokenEntity);

        // Generate the verification link using applicationUrl()
        String verificationLink = applicationUrl() + "/auth/verifyRegistration?token=" + verificationToken;

        // Log the verification link in the console
        log.info("Verification link: " + verificationLink);
        // Send the verification link to the user (you can implement this part)

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .name(request.getName())
                .build();
    }
    public String applicationUrl() {
        String protocol = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();

        return protocol + "://" + serverName + ":" + serverPort + contextPath;
    }
    public String verifyUser(String token) {
        // Find the verification token
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token);

        if (verificationToken ==null){
            return "invalid";
        }

        Calendar cal = Calendar.getInstance();

        if ((verificationToken.getExpirationTime().getTime() - cal.getTime().getTime() < 0)){
            // Delete the verification token
            //verificationTokenRepository.delete(verificationToken);
            return "expired";
        }
        // Find the user by ID
        User user = repository.findById(verificationToken.getId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Set user as verified
        user.setEnabled(true);
        verificationTokenRepository.delete(verificationToken);
        repository.save(user);

        return "valid";

    }
    private Date calculateExpirationDate(int expirationMinutes) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(new Date().getTime());
        calendar.add(Calendar.MINUTE, expirationMinutes);
        return new Date(calendar.getTime().getTime());
    }
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .name(user.getName())
                .build();
    }
    private Long getNextUserId() {
        List<User> existingUsers = repository.findAll();

        User newUser = new User();

        if (existingUsers.isEmpty()) {
            newUser.setId(1001L);
        } else {
            // Find the maximum existing user ID
            Long maxId = existingUsers.stream()
                    .map(User::getId)
                    .max(Long::compare)
                    .orElse(0L);

            // Set the new user ID
            newUser.setId(maxId + 1);
        }

        return newUser.getId(); // If the table is empty, start from 1001
    }
    public VerificationTokenResult generateNewVerificationToken(String OldToken) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(OldToken);
        if (verificationToken == null) {
            return new VerificationTokenResult(false, "Token not found");
        }

        // Update expirationTime (adjust this based on your requirements)
        Date newExpirationTime = calculateExpirationDate(EXPIRATION_MINUTES);
        verificationToken.setExpirationTime(newExpirationTime);

        // Generate a new token
        verificationToken.setToken(UUID.randomUUID().toString());

        // Save the updated verification token
        verificationTokenRepository.save(verificationToken);

        return new VerificationTokenResult(true, verificationToken);
    }
    public void resendVerificationTokenMail(Long user, VerificationToken verificationToken) {
        // Generate the verification link using applicationUrl()
        String verificationLink = applicationUrl() + "/auth/verifyRegistration?token=" + verificationToken.getToken();

        // Log the verification link in the console
        log.info("Verification link: " + verificationLink);
    }
}
