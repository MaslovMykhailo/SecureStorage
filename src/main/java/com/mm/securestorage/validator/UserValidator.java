package com.mm.securestorage.validator;

import com.mm.securestorage.model.User;
import com.mm.securestorage.service.user.UserService;
import com.nulabinc.zxcvbn.Zxcvbn;
import org.passay.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

import java.util.Arrays;

@Component
public class UserValidator implements Validator {

    private final PasswordValidator validator = new PasswordValidator(
        Arrays.asList(
            new LengthRule(8, 64),
            new UppercaseCharacterRule(1),
            new DigitCharacterRule(1),
            new SpecialCharacterRule(1),
            new NumericalSequenceRule(5, false),
            new AlphabeticalSequenceRule(5, false),
            new QwertySequenceRule(3, false),
            new WhitespaceRule()
        )
    );

    private final Zxcvbn passwordStrengthMeasurer = new Zxcvbn();

    @Autowired
    private UserService userService;

    @Override
    public boolean supports(Class<?> aClass) {
        return User.class.equals(aClass);
    }

    @Override
    public void validate(Object o, Errors errors) {
        User user = (User) o;

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "username", "NotEmpty");
        if (user.getUsername().length() < 8 || user.getUsername().length() > 64) {
            errors.rejectValue("username", "Size.userForm.username");
        }
        if (userService.findByUsername(user.getUsername()) != null) {
            errors.rejectValue("username", "Duplicate.userForm.username");
        }

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "password", "NotEmpty");
        if (!validator.validate(new PasswordData(user.getPassword())).isValid()) {
            errors.rejectValue("password", "Pattern.userForm.password");
        }
        if (passwordStrengthMeasurer.measure(user.getPassword()).getScore() < 3) {
            errors.rejectValue("password", "Strength.userForm.password");
        }

        if (!user.getPasswordConfirm().equals(user.getPassword())) {
            errors.rejectValue("passwordConfirm", "Diff.userForm.passwordConfirm");
        }
    }

}
