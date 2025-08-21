package org.example.authservice.annotation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import org.example.authservice.validator.UniqueEmailValidator;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = UniqueEmailValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface UniqueEmail {
    String message() default "This email already exists";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
