package com.decathlon.security.demosecurity.config;

import com.decathlon.security.demosecurity.service.SecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;

@Configuration
@EnableGlobalMethodSecurity(   // If you want to use annotation to secure something [Controller, service, ...]
                               // you can remove it if not needed or enable only what you want
        prePostEnabled = true,  // Use @PreAuthorize / @PostAuthorize ex: @PreAuthorize("hasRole('ROLE_ADMIN')")
        securedEnabled = true, // Use @Secured   ex: @Secured("ROLE_ADMIN")
        jsr250Enabled = true)  // Use @RolesAllowed ex: @RolesAllowed("ROLE_ADMIN")
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwksUri;

    @Value("${security.oauth2.resourceserver.jwt.issuer}")
    private String issuer;

    @Autowired
    private SecurityService securityService;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                    .antMatchers("/anonymous").permitAll()
                    .antMatchers("/admin").hasRole("ADMIN")
                    .antMatchers("/**").fullyAuthenticated()
                .and()
                    .csrf().disable() // Only because we are in API
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .oauth2ResourceServer()
                    .jwt()
                    .decoder(createDecoder())
                    .jwtAuthenticationConverter(this::convert);
        ;
    }


    private JwtDecoder createDecoder() {
        // Simple jwt decoder which validate signature against public key from jwks URI
        // This is mandatory
        NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(jwksUri);

        // We add a validation on the issue. The timestamp (expiration) validation is also added with this method
        OAuth2TokenValidator validator = JwtValidators.createDefaultWithIssuer(issuer);
        // If you want to have some specific filter, you can create a
        /*
            List<OAuth2TokenValidator<Jwt>> validators = new ArrayList();
            validators.add(new JwtTimestampValidator()); // MANDATORY
            validators.add(new JwtIssuerValidator(issuer)); // SHOULD HAVE
            validators.add(new MyAudienceValidator(...)); // Your validator...
            OAuth2TokenValidator validator=new DelegatingOAuth2TokenValidator(validators);
         */

        jwtDecoder.setJwtValidator(validator);

        return jwtDecoder;
    }

    private AbstractAuthenticationToken convert(Jwt jwt) {
        // Warning machine to machine call will use more and more client credential flow
        // There is no "sub" (subject) in this flow or if present, it must be equal to client_id claim.

        if (jwt.getSubject()==null || jwt.getSubject().equals(jwt.getClaimAsString("client_id"))) {
            // Machine to machine use case
            return securityService.buildM2MToken(jwt);
        } else {
            //User use case
            return securityService.buildUserToken(jwt);
        }
    }
}
