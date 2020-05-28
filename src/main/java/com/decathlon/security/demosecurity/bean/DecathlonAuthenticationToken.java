package com.decathlon.security.demosecurity.bean;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

import java.util.Collection;
import java.util.Map;

@Transient
public class DecathlonAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {
    private String name;
    private boolean isClientCredential;
    public DecathlonAuthenticationToken(String name, boolean isClientCredential,
                                        Jwt jwt, JsonNode details, Collection<? extends GrantedAuthority> authorities) {
        super(jwt, authorities);
        this.name=name;
        this.isClientCredential=isClientCredential;
        this.setDetails(details);
        this.setAuthenticated(true);
    }

    public Map<String, Object> getTokenAttributes() {
        return ((Jwt)this.getToken()).getClaims();
    }

    public String getName() {
        return name;
    }

    public boolean isClientCredential(){
        return this.isClientCredential;
    }
}