package nl.quintor.securityhandson.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * Deze wordt gebruikt door Spring Security om een response te maken
 * als een gebruiker niet geauthenticeerd is, maar dat wel moet zijn
 * om bij het beoogde endpoint te komen.
 */
public class UnauthenticatedHandler
        implements AuthenticationEntryPoint {
    @Override
    public void commence(
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse,
            AuthenticationException e)
            throws IOException {

        httpServletResponse.setStatus(401);
        httpServletResponse.getWriter()
                .write("{\"message\":\"You're not authenticated.\"}");
    }
}
