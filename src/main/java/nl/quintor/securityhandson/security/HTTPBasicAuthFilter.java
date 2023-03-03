package nl.quintor.securityhandson.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

/**
 * Dit is een hele simpele implementatie van HTTP Basic Authentication
 */
public class HTTPBasicAuthFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public HTTPBasicAuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String authorizationHeader = request.getHeader("Authorization");

            if (authorizationHeader != null) {
                String decoded = new String(Base64.getDecoder().decode(authorizationHeader.replace("Basic ", "")));

                String[] split = decoded.split(":");

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(split[0], split[1]);

                Authentication result = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

                SecurityContextHolder.getContext().setAuthentication(result);
            }

        } catch (Exception e) {
            // We clearen de SecurityContext voor de zekerheid als het proces fout gaat
            SecurityContextHolder.clearContext();
        }

        // We gaan altijd door naar het volgende filter
        filterChain.doFilter(request, response);
    }
}
