package com.mm.securestorage.web;

import com.mm.securestorage.model.User;
import com.mm.securestorage.service.security.SecurityService;
import com.mm.securestorage.service.user.UserService;
import com.mm.securestorage.validator.UserValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private SecurityService securityService;

    @Autowired
    private UserValidator userValidator;

    @GetMapping("/registration")
    public String registration(Model model) {
        if (securityService.isAuthenticated()) {
            return "redirect:/";
        }

        model.addAttribute("userForm", new User());

        return "registration";
    }

    @PostMapping("/registration")
    public String registration(@ModelAttribute("userForm") User userForm, BindingResult bindingResult) {
        userValidator.validate(userForm, bindingResult);

        if (bindingResult.hasErrors()) {
            return "registration";
        }

        securityService.hashUserPassword(userForm);
        userService.save(userForm);
        securityService.autoLogin(userForm.getUsername(), userForm.getPasswordConfirm());

        return "redirect:/home";
    }

    @GetMapping("/login")
    public String login(Model model, String error, String logout) {
        if (securityService.isAuthenticated()) {
            return "redirect:/";
        }

        if (error != null) {
            model.addAttribute("error", "Your username and password is invalid.");
        }

        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully.");
        }

        return "login";
    }

    @GetMapping({"/", "/home"})
    public String home(@ModelAttribute("userForm") User userForm, BindingResult bindingResult) {
        if (!securityService.isAuthenticated()) {
            return "redirect:/login";
        }

        try {
            String username = securityService.getwAuthenticatedUsername();
            User user = userService.findByUsername(username);

            String sensitiveData = securityService.getUserSensitiveData(user);
            userForm.setSensitiveData(sensitiveData);
        } catch (IllegalStateException error) {
            bindingResult.rejectValue("sensitiveData", "Illegal.userForm.sensitiveData");
        }

        return "home";
    }

    @PostMapping({"/", "/home"})
    public String home(@ModelAttribute("userForm") User userForm) {
        if (!securityService.isAuthenticated()) {
            return "redirect:/login";
        }

        String username = securityService.getAuthenticatedUsername();
        User user = userService.findByUsername(username);

        String sensitiveData = userForm.getSensitiveData();
        securityService.setUserSensitiveData(user, sensitiveData);

        userService.save(user);

        return "home";
    }

}
