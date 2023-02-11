package org.zerock.club.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.zerock.club.security.handler.ClubLoginSuccessHandler;

@Configuration
@EnableWebSecurity
@Log4j2
@EnableMethodSecurity(prePostEnabled = true)

public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {

        log.info("----------------------filterChain-------------------------");


//        http.authorizeHttpRequests()
//                .requestMatchers("/sample/all").permitAll()
//                .requestMatchers("/sample/member").hasAnyAuthority("USER","OAUTH2_USER")
//                .requestMatchers("/sample/admin").hasRole("ADMIN");


        http.formLogin();
        http.csrf().disable();
        http.logout();

        http.oauth2Login().successHandler(clubLoginSuccessHandler());

        http.rememberMe().tokenValiditySeconds(60*60*24*7);

        return http.build();
    }

//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails user = User.builder()
//                .username("user1")
//                .password("$2a$10$54b4w2aKbDkcEr5BLISfiubKcmZo7kVp5B0FqyUZ9SdMp9TXqNgxe")
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }

    @Bean
    public ClubLoginSuccessHandler clubLoginSuccessHandler() {
        return new ClubLoginSuccessHandler(passwordEncoder());
    }
}
