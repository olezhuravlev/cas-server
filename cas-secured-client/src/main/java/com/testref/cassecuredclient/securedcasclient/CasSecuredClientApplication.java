package com.testref.cassecuredclient.securedcasclient;

import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.AuthenticationEntryPoint;

@SpringBootApplication
public class CasSecuredClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(CasSecuredClientApplication.class, args);
    }

    @Bean
    public ServiceProperties serviceProperties() {

        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost:9090/login/cas");

        // Tells login service that username/password is required to gain access to the service every time.
        // It also gives the user access to all services/client without having to enter the credentials.
        // When logged out the user is logged out automatically from all services.
        serviceProperties.setSendRenew(false);

        return serviceProperties;
    }

    /**
     * Lets to know where our CAS-server is running.
     * When user accesses a client application secured by CAS-server, the bean AuthenticationEntryPoint is triggered
     * and the user is taken to CAS-server URL that is configured in this bean.
     *
     * @param serviceProperties
     * @return
     */
    @Bean
    @Primary
    public AuthenticationEntryPoint authenticationEntryPoint(ServiceProperties serviceProperties) {

        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();

        // When a user tries to login, the application will be redirected to this URL.
        entryPoint.setLoginUrl("http://localhost:6443/cas/login");

        entryPoint.setServiceProperties(serviceProperties);

        return entryPoint;
    }

    /**
     * 1. Once the user enters credentials and submits the page, the CAS-server authenticates the user and creates
     * a service ticket. This ticket is appended to URL and the user is taken to the requested client application.
     * 2. When the client application gets the ticket, this bean is used to validate its authenticity.
     * 3. If the ticket is valid then user is allowed to access the requested page.
     *
     * @return
     */
    @Bean
    public TicketValidator ticketValidator() {
        return new Cas30ServiceTicketValidator("http://localhost:6443/cas");
    }

    /**
     * Binds ticker validator along with service properties into authentication provider bean.
     *
     * @return
     */
    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {

        CasAuthenticationProvider provider = new CasAuthenticationProvider();

        // Add beans.
        provider.setServiceProperties(serviceProperties());
        provider.setTicketValidator(ticketValidator());

        // Provide user details to CAS-server?
        provider.setUserDetailsService((s) -> new User(
                "casuser",
                "password",
                true,
                true,
                true,
                true,
                AuthorityUtils.createAuthorityList("ROLE_ADMIN")));

        // A Key is required so CasAuthenticationProvider can identify tokens it previously authenticated.
        provider.setKey("CAS_PROVIDER_PORT_9090");

        return provider;
    }
}
