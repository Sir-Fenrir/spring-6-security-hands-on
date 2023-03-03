package nl.quintor.securityhandson.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

/**
 * Deze wordt gebruikt door Spring Security om een response te maken
 * als een gebruiker wel geauthenticeerd is, maar niet de juiste rechten
 * heeft om het beoogde endpoint te gebruiken.
 */
public class UserAccessDeniedHandler
        implements AccessDeniedHandler {
    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException)
            throws IOException {

        response.setStatus(403);
        response.getWriter()
                .write("{\"message\":\"You're not allowed in here.\"}");
    }
}
