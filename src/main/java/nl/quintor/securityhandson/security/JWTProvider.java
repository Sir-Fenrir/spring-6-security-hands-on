package nl.quintor.securityhandson.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;

/**
 * Klasse voor het genereren en valideren van JSON Web Tokens
 */
@Component
public class JWTProvider {

    // We gebruiken een secret key voor het genereren van een JWT, zodat niemand anders dat kan doen
    private final SecretKey secretKey;
    // We moeten ook instellen hoe lang een token geldig blijft
    private final long validityInMilliseconds = 600000; // 10 minutes


    public JWTProvider(@Value("${jwt.secretkey}") String secretKey) {
        this.secretKey = Keys.hmacShaKeyFor(Base64.getEncoder().encode(secretKey.getBytes()));
    }

    /**
     * We maken een token voor een gebruikersnaam en gegeven rollen
     *
     * @param username    De gebruikersnaam
     * @param authorities De rollen van de gebruiker
     * @return Een JSON Web Token, gesigneerd met de secret key
     */
    public String createToken(String username, Collection<? extends GrantedAuthority> authorities) {
        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return createToken(username, roles);
    }

    private String createToken(String username, List<String> roles) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + validityInMilliseconds);
        return Jwts.builder()
                .setSubject(username)
                .addClaims(Map.of("roles", roles))
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(secretKey)
                .compact();
    }

    /**
     * Aangezien een token niet zomaar aangepast kan worden,
     * kunnen we de inhoud gebruiken om een Authentication object aan te maken,
     * zo besparen we tripjes naar de database!
     *
     * @param tokenString De JWT
     * @return Het {@link Authentication} object gebaseerd op de gebruiker uit dit token
     */
    public Authentication getAuthentication(String tokenString) {
        Claims claims = getClaims(tokenString);
        String user = claims.getSubject();
        List<SimpleGrantedAuthority> roles = ((List<String>) claims.get("roles"))
                .stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        UserDetails userDetails = new User(user, "", roles);
        return new UsernamePasswordAuthenticationToken(userDetails, "",
                roles);
    }

    /**
     * Kijk of de token bijna verloopt. Zo ja, dan maken we een nieuwe.
     *
     * @param tokenString De token
     * @return null als de token nog niet verloopt, anders een nieuw token
     */
    public String getRefreshToken(String tokenString) {
        Claims claims = getClaims(tokenString);
        Date expiration = claims.getExpiration();
        if (new Date(new Date().getTime() + validityInMilliseconds / 10).after(expiration)) {
            String user = claims.getSubject();
            return createToken(user, (List<String>) claims.get("roles"));
        }
        return null;
    }

    /**
     * Kijk of er een token in het gegeven HTTP Request zit
     *
     * @param req Het HTTP Request
     * @return De waarde van de Authorization header, als die er is
     */
    public String getToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Parse de JWT en haal de claims er uit.
     *
     * @param tokenString De token
     * @return De claims
     */
    private Claims getClaims(String tokenString) {
        Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(tokenString);
        return claims.getBody();
    }
}
