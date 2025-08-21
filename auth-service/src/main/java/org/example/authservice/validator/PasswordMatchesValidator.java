package org.example.authservice.validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.example.authservice.annotation.PasswordMatches;
import org.example.authservice.dto.auth.RegistrationRequest;

public class PasswordMatchesValidator implements ConstraintValidator<PasswordMatches, RegistrationRequest> {
    @Override
    public boolean isValid(RegistrationRequest request, ConstraintValidatorContext constraintValidatorContext) {
        if (request == null) {
            return true;
        }
        return request.password().equals(request.confirmPassword());
    }
}
