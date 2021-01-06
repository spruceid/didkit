package com.spruceid.didkitexample.config;

import com.spruceid.didkitexample.auth.VPAuthenticationFilter;
import com.spruceid.didkitexample.auth.VPAuthenticationProvider;
import com.spruceid.didkitexample.user.UserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@AllArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserService userService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private final StringRedisTemplate redisTemplate;

    public AuthenticationProvider customAuthenticationProvider() {
        return new VPAuthenticationProvider(userService);
    }

    public VPAuthenticationFilter authenticationFilter() throws Exception {
        return new VPAuthenticationFilter(authenticationManagerBean(), redisTemplate);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers(
                        "/favicon.ico",
                        "/manifest.json",
                        "/version",
                        "/sign-up/**",
                        "/sign-in/**",
                        "/verifiable-presentation-request/**",
                        "/credential-offer/**",
                        "/wss/**",
                        "/scripts/**"
                )
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/sign-in")
                .loginProcessingUrl("/sign-in")
                .permitAll();
    }

    @Autowired
    protected void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
        auth.authenticationProvider(customAuthenticationProvider());
    }
}
