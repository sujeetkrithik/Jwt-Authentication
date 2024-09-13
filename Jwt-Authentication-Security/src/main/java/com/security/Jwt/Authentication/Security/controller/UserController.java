package com.security.Jwt.Authentication.Security.controller;

import com.security.Jwt.Authentication.Security.entity.Users;
import com.security.Jwt.Authentication.Security.repository.UserRepository;
import com.security.Jwt.Authentication.Security.service.UsersDetailService;
import com.security.Jwt.Authentication.Security.webtoken.JwtService;
import com.security.Jwt.Authentication.Security.webtoken.LoginForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UsersDetailService userDetailService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register/user")
    public Users createUser (@RequestBody Users user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @GetMapping("/home")
    public String home(){
        return "Home";
    }

    @GetMapping("/admin/home")
    public String admin(){
        return "Home Admin";
    }

    @GetMapping("/user/home")
    public String user(){
        return "Home User";
    }

    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody LoginForm loginForm){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginForm.username(), loginForm.password()
        ));

        if(authentication.isAuthenticated()){
         return  jwtService.generateToken(userDetailService.loadUserByUsername(loginForm.username()));
        }
        else {
            throw new UsernameNotFoundException("Invalid Credentials");
        }
    }

}
