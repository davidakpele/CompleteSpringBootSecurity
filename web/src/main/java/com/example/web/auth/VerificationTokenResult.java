package com.example.web.auth;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class VerificationTokenResult {
    private boolean success;
    private Object data; // This can be a VerificationToken or an error message
}