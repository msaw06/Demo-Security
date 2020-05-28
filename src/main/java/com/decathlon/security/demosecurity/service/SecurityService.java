package com.decathlon.security.demosecurity.service;

import com.decathlon.security.demosecurity.bean.DecathlonAuthenticationToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.NullNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

@Service
/**
 * Security service: Goal is to create a user object from JWT.
 *  It is put in a separate service as @Cacheable will only work when call come from outside.
 */
public class SecurityService {

    @Value("${security.oauth2.resourceserver.jwt.userinfo-endpoint}")
    private String userInfoEndpoint;

    private RestTemplate restTemplate;

    public SecurityService(RestTemplateBuilder rtb){
        restTemplate=rtb.build();
    }

    // Best practice to cache that.
    // Cacheable do only work if call come from another service!
    @Cacheable(value = "M2M_AUTHENTICATION_TOKEN", key = "#jwt.claims.get('client_id')")
    public AbstractAuthenticationToken buildM2MToken(Jwt jwt) {
        // M2M => no sub is possible.
        // Here I set a name as `client_id` so that It is not empty.
        String name = jwt.getSubject() != null ? jwt.getSubject() : jwt.getClaimAsString("client_id");

        // Call database to get role from this client_id... Here we assume empty role
        Collection<GrantedAuthority> authorities = Collections.emptyList();

        return new DecathlonAuthenticationToken(name, true, jwt, NullNode.getInstance(), authorities);
    }


    // THE CACHE IS MANDATORY HERE!!!!!!!!!!!!!!
    // It has to be enable with "@EnableCaching"  Check DemoSecurityApplication class for that
    // YOU NEED TO ADD A CORRECT CACHE MANAGER (based on ehcache, redis, ...) AS DEPENDENCY
    // and set it up on application.yml
    //   HERE IT IS THE DEFAULT IMPLEMENTATION WHICH IS A SIMPLE MAP!!!!! (no eviction, no size control...)
    // CACHE NEED TO BE BIG ENOUGH TO HAVE SMALL NUMBER OF REQUEST ON UserInfo endpoint!!
    // It is mandatory to test if the cache is working fine ( cache hit / cache miss!! )
    // Cacheable do only work if call come from another service!
    @Cacheable(value = "USER_AUTHENTICATION_TOKEN", key = "#jwt.subject")
    public AbstractAuthenticationToken buildUserToken(Jwt jwt) {
        JsonNode detail=findUserFromJwt(jwt);

        Collection<GrantedAuthority> authorities = this.extractAuthorities(jwt, detail);

        return new DecathlonAuthenticationToken(jwt.getSubject(), false, jwt, detail, authorities);
    }

    private JsonNode findUserFromJwt(@NonNull Jwt jwt) {
        ResponseEntity<JsonNode> responseEntity = restTemplate
                .exchange(userInfoEndpoint, HttpMethod.POST, buildHttpEntityParameters(jwt.getTokenValue()),
                        JsonNode.class);

        if (responseEntity.getStatusCode().is2xxSuccessful()){
            return responseEntity.getBody();
        }
        throw new IllegalStateException("No user could be retrieved with provided JWT");
    }

    HttpEntity<String> buildHttpEntityParameters(String tokenValue) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", "Bearer " + tokenValue);
        return new HttpEntity<>("parameters", headers);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt, JsonNode detail) {
        // Call database to get role from subject, via xxxx
        //  List<String> roles=findRoleByUid(jwt.getSubject());

        // Add role per properties from detail
        // For instance, in DB a table like:   property_name | property_value | role
        // Will be processed like:
        // For each (propertyName,propertyValue,role){
        //    if propertyValue.equald(detail.get(propertyName).asText(propertyName)) roles.add(role)
        //     Be ware of the list!!
        // }

        return Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }
}
