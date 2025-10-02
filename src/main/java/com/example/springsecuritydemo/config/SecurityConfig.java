package com.example.springsecuritydemo.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;


@Slf4j
@Configuration
public class SecurityConfig {

    private final CustomOidcUserService customOidcUserService;
    private final DataSource dataSource;

    public SecurityConfig(CustomOidcUserService customOidcUserService, DataSource dataSource) {
        this.customOidcUserService = customOidcUserService;
        this.dataSource = dataSource;
    }

//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//                .userDetailsService(userDetailsService())
//                .passwordEncoder(passwordEncoder())
////                .jdbcAuthentication()
////                .dataSource(dataSource)
//        ;
//    }


    /**
     * This is where the security configuration is done.
     * <p> cors -> Cross-Origin Resource Sharing
     * <p> csrf -> Cross-Site Request Forgery
     *
     * @param http
     * @return SecurityFilterChain
     * @throws Exception
     */

    @Bean
    public SecurityFilterChain securityFilterChainEmpty(HttpSecurity http) throws Exception {
        http
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.disable())
                .csrf(csrf -> csrf.disable())

//                .httpBasic(Customizer.withDefaults())
//                .formLogin(Customizer.withDefaults())
                .oauth2Login(oauth ->
                        oauth.userInfoEndpoint(userInfo -> {
                            userInfo.oidcUserService(customOidcUserService);
                        })
                )
                .oauth2ResourceServer(oauth ->
                        oauth.jwt(Customizer.withDefaults())
                )
                .logout(logout -> logout
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )
//                .userDetailsService(oauth2UserService)
        ;

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
//        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//        grantedAuthoritiesConverter.setAuthoritiesClaimName("realm_access.roles");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
//        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new CustomJwtRolesConverter());
        return jwtAuthenticationConverter;
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
    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }


    /**
     * This method is to create the UserDetailsService bean.
     * <p> UserDetailsService fetches the UserDetails for the user
     * <p> InMemoryUserDetailsManager -> create userDetails at runtime, good for prototyping
     * <p> JdbcUserDetailsManager -> fetches userDetails from defined dataSource (JDBC). DataSource is required to have the Users table and Authorities table
     *
     * @return UserDetailsService
     */


//    @Bean
    public UserDetailsService userDetailsService() {
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