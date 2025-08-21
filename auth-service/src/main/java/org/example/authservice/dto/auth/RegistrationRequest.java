package org.example.authservice.dto.auth;

import jakarta.validation.constraints.*;

public record RegistrationRequest(
        @NotBlank(message = "Full name must not be empty")
        String fullName,

        @NotBlank(message = "Email must not be empty")
        @Email(message = "Email should be valid")
        String email,

        @NotBlank(message = "Password must not be empty")
        @Size(min = 6, message = "Password must be at least 6 characters")
        @Pattern(regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*\\W).*$",
                message = "Password must contain at least one uppercase letter, one lowercase letter, one digit and one special character")
        String password,

        @NotBlank(message = "Confirm password must not be empty")
        String confirmPassword
) {
}