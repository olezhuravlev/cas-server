package com.testref.cassecuredclient.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class CasController {

    @RequestMapping(value = "/secured", method = RequestMethod.GET)
    public String secured(ModelMap modelMap) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.getPrincipal() != null && auth.getPrincipal() instanceof UserDetails) {
            modelMap.put("authusername", ((UserDetails) auth.getPrincipal()).getUsername());
        }

        return "secured";
    }
}
