package com.security.springsecuritydemo.security;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
public class CommonController {

  @GetMapping({"/", "/home", ""})
  String home(){
    log.info("home>>");
    return "home";
  }

  @GetMapping("/deny")
  String deny(){
    log.info("deny>>");
    return "deny";
  }

  @GetMapping("/role_user")
  String user(){
    log.info("role user>>");
    return "role_user";
  }
  @GetMapping("/role_admin")
  String admin(){
    log.info("role_admin>>");
    return "role_admin";
  }
  @GetMapping("/public")
  String publicPage(){
    log.info("public>>");
    return "public";
  }


  @GetMapping("/login1")
  String login() {
    log.info("login1>>");
    return "login1";
  }

  @GetMapping("/fail")
  String fail() {
    log.info("fail>>");
    return "fail";
  }
}
