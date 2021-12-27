package com.security.springsecuritydemo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Entry point 는 로그화면 같은 인증을 할 수 있는 통로라고 생각하면 된다.
 * 웹브라우저의 Entry point 는 로그인 화면인데 REST 는 이런 게 없기 때문에 수정해 주어야 한다.
 * 인증 실패 시에 결과 처리에 가까운데, REST 에서는 기본 html 반환이 적합하지 않다.
 */
@Component
@Slf4j
public class CustomBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
    super.commence(request, response, authException);
    log.info("headerNames = {}",request.getHeaderNames());
    log.info("dispatcherType = {}",request.getDispatcherType());
    log.info(request.getAuthType());
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);//401
    response.addHeader("WWW-Authenticate", "Basic realm=" + super.getRealmName() + "");
    PrintWriter writer = response.getWriter(); // 기본인 html 응답 대신 REST 를 위하여 메시지를 보냄
    writer.println("HTTP Status 401 - " + authException.getMessage());
  }

  @Override
  public void afterPropertiesSet() {
    super.setRealmName("user");// 어디에 필요한지 ?
    super.afterPropertiesSet();
  }
}
