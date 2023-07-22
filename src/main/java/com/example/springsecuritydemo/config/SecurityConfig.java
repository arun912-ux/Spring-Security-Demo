package com.example.springsecuritydemo.config;

import com.example.springsecuritydemo.config.filter.CsrfCookieFilter;
import com.example.springsecuritydemo.config.filter.JWTTokenGenerationFilter;
import com.example.springsecuritydemo.config.filter.JWTTokenValidationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;

import javax.sql.DataSource;
import java.util.List;



@Component
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {


    private final PasswordEncoder encoder;
    private final DataSource dataSource;

    private final UserDetailsService userDetailsService;


    public SecurityConfig(@Lazy PasswordEncoder encoder, DataSource dataSource, @Lazy UserDetailsService userDetailsService) {
        this.encoder = encoder;
        this.dataSource = dataSource;
        this.userDetailsService = userDetailsService;
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(encoder)
//                .jdbcAuthentication()
//                .dataSource(dataSource)
        ;
    }


    /**
     *
     * This is where the security configuration is done.
     * <p> cors -> Cross-Origin Resource Sharing
     * <p> csrf -> Cross-Site Request Forgery
     *
     * @param http
     * @return SecurityFilterChain
     * @throws Exception
     */


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


        http
                // these 2 lines are needed for browser session
//                .sessionManagement(session -> {
//                    session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
//                    session.maximumSessions(2);
//                })
//                .securityContext(context -> context.requireExplicitSave(false))
                // these 2 lines are for telling Spring Security to be stateless (No Session ID required)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

//                .cors(cors -> cors.disable())
                .cors(cors -> cors.configurationSource(req -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(List.of("http://localhost:4200", "http://192.168.1.3:4200"));
                    config.setAllowedMethods(List.of(HttpMethod.POST.toString()));
                    config.setExposedHeaders(List.of("Authorization"));
                    config.setMaxAge(60L);
                    return config;
                }))

//                .csrf(Customizer.withDefaults())
//                .csrf(csrf -> csrf.disable())
                .csrf(csrf -> {
                    csrf.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler());
                    csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
                    csrf.ignoringRequestMatchers("/login", "/register", "/logout", "/");
                })



                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTTokenGenerationFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new JWTTokenValidationFilter(), BasicAuthenticationFilter.class)


                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/", "/login", "/user").permitAll();
//                    auth.requestMatchers("/admin/**").hasRole("ADMIN");           // this can be replaced with method level security
                    auth.anyRequest().authenticated();
                })


//                .formLogin(Customizer.withDefaults())
                .formLogin(login -> {
//                    login.loginProcessingUrl("/login");
//                    login.defaultSuccessUrl("/home");
//                    login.loginPage("/login");
                    login.failureUrl("/login?error");
                })


                .logout(logout -> {
                    logout.clearAuthentication(true);
                    logout.deleteCookies("JSESSIONID", "remember-me", "XSRF-TOKEN", "Authorization", "CSRF-TOKEN", "X-XSRF-TOKEN");
                    logout.invalidateHttpSession(true);
                })


                .httpBasic(Customizer.withDefaults())

//                .userDetailsService(userDetailsService)

                .rememberMe(rme -> rme.alwaysRemember(false))

        ;

        return http.build();

    }


    /**
     * This method is to create the PasswordEncoder bean
     * <p> NoOpPasswordEncoder -> Plain text password
     * <p> BCryptPasswordEncoder -> Hashing password
     *
     * @return PasswordEncoder
     */


    @Bean
    @SuppressWarnings("deprecation")
    public PasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }


    /**
     *
     * This method is to create the UserDetailsService bean.
     * <p> UserDetailsService fetches the UserDetails for the user
     * <p> InMemoryUserDetailsManager -> create userDetails at runtime, good for prototyping
     * <p> JdbcUserDetailsManager -> fetches userDetails from defined dataSource (JDBC). DataSource is required to have the Users table and Authorities table
     *
     * @return UserDetailsService
     */


    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails admin = User.builder()
                .username("admin")
                .password("pass")
                .roles("ADMIN")
                .accountExpired(false)
                .accountLocked(false)
                .disabled(false)
                .build();


        return new InMemoryUserDetailsManager(admin);
//        return new JdbcUserDetailsManager(dataSource);
    }






}


