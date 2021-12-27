package com.security.springsecuritydemo.security;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
public class CommonController {

  @GetMapping("/")
  String home(){
    log.info("home>>");
    return "home";
  }

  @GetMapping("/security")
  String security(){
    log.info("security>>");
    return "security";
  }

  @GetMapping("/role")
  String role(){
    log.info("role>>");
    return "role";
  }

  @GetMapping("/login1")
  String login() {
    log.info("login>>");
    return "login1";
  }

}
