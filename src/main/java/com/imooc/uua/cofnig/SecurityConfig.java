package com.imooc.uua.cofnig;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imooc.uua.security.filter.RestAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.HashMap;
import java.util.Map;

/**
 * @author mCarr
 */
@EnableWebSecurity(debug = false)
@Slf4j
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final ObjectMapper objectMapper;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(req -> req
                        .antMatchers("/authorize/**").permitAll()
                        .antMatchers("/admin/**").hasRole("ADMIN")
                        .antMatchers("/api/**").hasRole("USER")
                        .anyRequest().authenticated())
                        .csrf(csrf -> csrf.ignoringAntMatchers("/authorize/**","/admin/**","/api/**"))
//                .formLogin(form -> form.loginPage("/login")
//                        .defaultSuccessUrl("/")
//                        .successHandler(jsonAuthenticationSuccessHandler())
//                        .failureHandler(jsonAuthenticationFailureHandler())
//                        .permitAll())
                .addFilterAfter(restAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

//                .logout(logout -> logout.logoutUrl("/perform_logout"))
//                .httpBasic(Customizer.withDefaults())
//                .rememberMe(rememberme -> rememberme.tokenValiditySeconds(30 * 24 *3600).rememberMeCookieName("someKeyToRemember"));
    }

    private AuthenticationFailureHandler jsonAuthenticationFailureHandler() {
        return (req,res,exception)->{
            val objectMapper = new ObjectMapper();
            res.setStatus(HttpStatus.UNAUTHORIZED.value());
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            res.setCharacterEncoding("UTF-8");
            val errorData = new HashMap<String,String>(){
                {
                    put("title","认证失败");
                    put("details",exception.getMessage());
                }
            };
            res.getWriter().println(objectMapper.writeValueAsString(errorData));
        };
    }

    private AuthenticationSuccessHandler jsonAuthenticationSuccessHandler() {
        ObjectMapper objectMapper = new ObjectMapper();
        return (req,res,auth) ->{
            res.setStatus(HttpStatus.OK.value());
            res.getWriter().println(objectMapper.writeValueAsString(auth));
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

        val idForDefault = "bcrypt";

        val encodeMap = new HashMap<String,PasswordEncoder>(){
            {
                put(idForDefault,new BCryptPasswordEncoder());
                put("SHA-1",new MessageDigestPasswordEncoder("SHA-1"));
            }
        };

        return new DelegatingPasswordEncoder(idForDefault,encodeMap);
    }

    public RestAuthenticationFilter restAuthenticationFilter() throws Exception {
        RestAuthenticationFilter filter = new RestAuthenticationFilter(objectMapper);
        filter.setAuthenticationSuccessHandler(jsonAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(jsonAuthenticationFailureHandler());
        filter.setAuthenticationManager(authenticationManager());
        filter.setFilterProcessesUrl("/authorize/login");
        return filter;
    }
}
