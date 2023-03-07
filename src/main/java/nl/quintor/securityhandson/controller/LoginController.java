package nl.quintor.securityhandson.controller;

import nl.quintor.securityhandson.security.JWTProvider;
import nl.quintor.securityhandson.security.LoginDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class LoginController {

    private final AuthenticationManager authenticationManager;

    private final JWTProvider jwtProvider;

    public LoginController(AuthenticationManager authenticationManager, JWTProvider jwtProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtProvider = jwtProvider;
    }

    /**
     * Om in te loggen en een JWT te krijgen
     *
     * @param login de request body
     * @return Een response met een header waar de JWT in zit
     */
    @PostMapping
    public ResponseEntity<Void> login(@RequestBody LoginDTO login) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()));

        UserDetails user = (UserDetails) authentication.getPrincipal();

        String token = jwtProvider.createToken(user.getUsername(), user.getAuthorities());

        return ResponseEntity.ok()
                .header("jwt-token", token)
                .build();
    }


}
