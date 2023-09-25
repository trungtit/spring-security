package spring_boot.spring_security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import spring_boot.spring_security.config.handler.CustomAuthenticationFailureHandler;
import spring_boot.spring_security.config.handler.CustomAuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled=true,prePostEnabled=true,jsr250Enabled=true)
public class SecurityConfig {

    @Autowired
    private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;


    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user1 = User.builder()
                .username("user1")
                .password(encoder().encode("123456"))
                .roles("ADMIN")
                .build();
        UserDetails user2 = User.builder()
                .username("user2")
                .password(encoder().encode("123456"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user1, user2);
    }



    @Bean
    public PasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .antMatchers("/logout").permitAll()
                        .antMatchers("/home").hasRole("USER")
                        .antMatchers("/hello").hasRole("ADMIN")
                        .anyRequest().authenticated()
                ).formLogin((form) -> form
                        .loginPage("/login").permitAll()
                )
                .logout((logout) -> logout.permitAll())
                .rememberMe(r->r.key("uniqueAndSecret"));
        http.csrf(c->c.disable());
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }
}

