package com.imooc.uua.cofnig;

import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * @author mCarr
 */
@EnableWebSecurity(debug = true)
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(req -> req.anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login")
                        .successHandler(jsonAuthenticationSuccessHandler())
                        .permitAll())
                .csrf(Customizer.withDefaults())
                .logout(logout -> logout.logoutUrl("/perform_logout"))
                .httpBasic(Customizer.withDefaults())
                .rememberMe(rememberme -> rememberme.tokenValiditySeconds(30 * 24 *3600).rememberMeCookieName("someKeyToRemember"));
    }

    private AuthenticationSuccessHandler jsonAuthenticationSuccessHandler() {
        return (req,res,auth) ->{
            res.setStatus(HttpStatus.OK.value());
            res.getWriter().println();
            log.debug("认证成功");
        };
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password(passwordEncoder().encode("12345678")).roles("USER","ADMIN");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().mvcMatchers("/public/**","/error")
            .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
