package com.decathlon.security.demosecurity.controller;

import com.decathlon.security.demosecurity.bean.DecathlonAuthenticationToken;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
    @GetMapping("/anonymous")
    public String anonymous(){
        return "anonymous: "+ SecurityContextHolder.getContext().getAuthentication().getName();
    }

    @GetMapping("/authenticated")
    public String authenticated(){
        return "authenticated: "+ SecurityContextHolder.getContext().getAuthentication().getName()+
                ": Is it client credential?: "+((DecathlonAuthenticationToken)SecurityContextHolder.getContext().getAuthentication()).isClientCredential();
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin: "+ SecurityContextHolder.getContext().getAuthentication().getName();
    }

    /*
     * Secure via annotation is possible. NOTE: it need to be enable in the configuration!!
     * check the @EnableGlobalMethodSecurity in SecurityConfiguration class
     */
    @GetMapping("/adminWithAnnotation")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String admin2(){
        return "admin2: "+ SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
