package nl.quintor.securityhandson.config;

import nl.quintor.securityhandson.security.HTTPBasicAuthFilter;
import nl.quintor.securityhandson.security.UnauthenticatedHandler;
import nl.quintor.securityhandson.security.UserAccessDeniedHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
                .authorizeHttpRequests(r -> {
                    r.requestMatchers("/hello_world").hasRole("WORLD");
                    r.requestMatchers("/hello_universe").hasRole("UNIVERSE");
                })
                .addFilterBefore(new HTTPBasicAuthFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> {
                    e.authenticationEntryPoint(new UnauthenticatedHandler());
                    e.accessDeniedHandler(new UserAccessDeniedHandler());
                })
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /**
     * Op deze manier kunnen we de gebruikte AuthenticationManager beschikbaar stellen als bean,
     * zodat we die makkelijk kunnen injecteren waar we maar willen.
     *
     * @param authenticationConfiguration Een export van de authenticatie configuratie
     * @return De gebruikte AuthenticationManager
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * We maken hier een UserDetailsService die via JDBC de gebruikers ophaalt.
     */
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    /**
     * De standaard password encoder om te gebruiken
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
