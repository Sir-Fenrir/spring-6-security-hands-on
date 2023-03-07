package nl.quintor.securityhandson.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * We gebruiken dit filter om te kijken of er een JWT in het request zit,
 * zo ja, dan gaan we kijken of die nog valide is.
 */
public class JWTFilter extends OncePerRequestFilter {

    // We gebruiken deze provider om JWT's te verifiëren
    private final JWTProvider jwtProvider;

    public JWTFilter(JWTProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    /**
     * Kijk of het request een valide JWT heeft.
     * Als dat het geval is, maken we een {@link Authentication} object en
     * die plaatsen we dan in de {@link SecurityContextHolder}.
     *
     * @param request     Het HTTP Request dat de FilterChain heeft geactiveerd
     * @param response    Het HTTP Response dat uiteindelijk terug gaat naar de gebruiker
     * @param filterChain De filter chain
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Haal het token uit het request
        String token = jwtProvider.getToken(request);
        try {
            // Kijk of er wel een token is
            if (token != null) {
                // We maken er een Authentication object van en zetten die in de SecurityContextHolder
                Authentication authentication = jwtProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Kijk of het token bijna verloopt, zo ja, dan maken we een nieuw token voor de gebruiker
                String newToken = jwtProvider.getRefreshToken(token);
                if (newToken != null) {
                    // We plaatsen het in een nieuwe header
                    response.addHeader("jwt-new-token", newToken);
                }
            }
        } catch (Exception e) {
            // Mocht er iets fout gaan, dan willen we zeker zijn dat de SecurityContextHolder leeg is.
            SecurityContextHolder.clearContext();
        }

        // We laten het filter gewoon doorgaan, ook al zou de authenticatie falen.
        // Het is aan Spring om te kijken of de authenticatie volstaat.
        filterChain.doFilter(request, response);
    }

}
