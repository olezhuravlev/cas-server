package com.testref.cassecuredclient;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.Arrays;

@EnableWebSecurity
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private AuthenticationProvider authenticationProvider;
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    public SpringSecurityConfig(CasAuthenticationProvider casAuthenticationProvider, AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationProvider = casAuthenticationProvider;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .regexMatchers("/secured.*", "/login")
                .authenticated()
                .and()
                .authorizeRequests()
                .regexMatchers("/")
                .permitAll()
                .and()
                .httpBasic()
                .authenticationEntryPoint(authenticationEntryPoint);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        // Tell the builder to user the provider.
        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    protected AuthenticationManager authenticationManager() {
        // The manager should use the provider.
        return new ProviderManager(Arrays.asList(authenticationProvider));
    }

    /**
     * This filter intercepts the requests and does CAS ticket validation.
     *
     * @param serviceProperties
     * @return
     * @throws Exception
     */
    @Bean
    public CasAuthenticationFilter casAuthenticationFilter(ServiceProperties serviceProperties) throws Exception {

        CasAuthenticationFilter filter = new CasAuthenticationFilter();

        filter.setServiceProperties(serviceProperties);
        filter.setAuthenticationManager(authenticationManager());

        return filter;
    }
}
