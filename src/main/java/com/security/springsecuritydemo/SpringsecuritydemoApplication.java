package com.security.springsecuritydemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collection;

@SpringBootApplication
public class SpringsecuritydemoApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringsecuritydemoApplication.class, args);


//    SecurityContext context = SecurityContextHolder.createEmptyContext(); // (1)
//    Authentication authentication =
//      new TestingAuthenticationToken("user", "1234", "ROLE_USER11"); // (2)
//    context.setAuthentication(authentication);
//
//    SecurityContextHolder.setContext(context); // (3)
//
//
//
//    String username = authentication.getName();
//    Object principal = authentication.getPrincipal();
//    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//
//    System.out.println("SpringsecuritydemoApplicationTests.getAuthUser");
//    System.out.printf("principal %s\n", principal.toString());
//    System.out.println("username : "+ username);
//    System.out.println("authorities = " + authorities.toString());
  }
}
