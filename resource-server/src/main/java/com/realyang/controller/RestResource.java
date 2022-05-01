package com.realyang.controller;

import com.realyang.domain.UserInfo;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author realyangex@126.com
 * @date 2021/9/22 15:33
 */
@Controller
public class RestResource {

    @PreAuthorize("hasAuthority('user')")
    @RequestMapping("/api/user")
    public ResponseEntity<UserInfo> profile() {

        UserInfo profile = new UserInfo();
        profile.setName("test");
        profile.setEmail("email");

        return ResponseEntity.ok(profile);
    }
}
