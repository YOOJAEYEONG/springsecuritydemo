package com.security.springsecuritydemo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.util.Collection;

@SpringBootTest
class SpringsecuritydemoApplicationTests {

  @Test
  void contextLoads() {
//    String salt = KeyGenerators.string().generateKey(); // generates a random 8-byte salt that is then hex-encoded
//    Encryptors.stronger("password", "salt");
//    Encryptors.text("password", "salt");
    SecurityContext context = SecurityContextHolder.createEmptyContext(); // (1)
    Authentication authentication =
      new TestingAuthenticationToken("user", "1234", "ROLE_USER11"); // (2)
    context.setAuthentication(authentication);

    SecurityContextHolder.setContext(context); // (3)
  }

  @Test
  void getAuthUser(){
    SecurityContext context = SecurityContextHolder.getContext();
    Authentication authentication = context.getAuthentication();
    String username = authentication.getName();
    Object principal = authentication.getPrincipal();
    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

    System.out.println("SpringsecuritydemoApplicationTests.getAuthUser");
    System.out.println("username : "+ username);
    System.out.println("authorities = " + authorities.toString());
  }

}
