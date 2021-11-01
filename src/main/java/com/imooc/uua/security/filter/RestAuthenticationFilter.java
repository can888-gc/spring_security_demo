package com.imooc.uua.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

@RequiredArgsConstructor
public class RestAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authRequest;

        try {
            InputStream inputStream = request.getInputStream();
            val info = objectMapper.readTree(inputStream);
            String username = info.get("username").textValue();
            String password = info.get("password").textValue();
            authRequest = new UsernamePasswordAuthenticationToken(username,password);
        } catch (IOException e) {
            e.printStackTrace();
            throw new BadCredentialsException("找不到用户名密码");
        }
        setDetails(request,authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }
}
