package com.security.springsecuritydemo.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Slf4j
@EnableWebSecurity //스프링 시큐리티의 웹 보안 지원을 활성화하고 스프링 MVC 통합을 제공합니다.
@RequiredArgsConstructor
public class CustomWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {



  private final CustomBasicAuthenticationEntryPoint customBasicAuthenticationEntryPoint;


  /*
    http
      .authorizeRequests()
        //  ROLE_SPITTER 권한이 있는 사용자를 요구
        .antMatchers(HttpMethod.POST,".spittles").hasAuthority("ROLE_SPITTER")
        //  ROLE_ 접두사를 자동 적용시켜주기 위한 hasRole() 메소드를 사용
        .antMatchers("/spiiters/me").hasRole("SPITTER")
  */

  /**
   * configure(HttpSecurity) : 보안되어야 하는 URL 경로와 보안되지 않아야 하는 URL 경로를 정의합니다.
   * 원하는 필터를 추가하거나 사용자 정의할 수 있다.
   * @param http
   * @throws Exception
   */
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    super.configure(http);

    http
      .csrf().disable()
        /*
         *  선택한 URL에 HTTPS를 적용 :
         *  안전한 채널이 요구하는지 확인하고 자동적으로 요청을 HTTPS로 리다이렉션 시켜준다.
         */
//        .requiresChannel()
//          .anyRequest()
//            .requiresSecure()
//            .and()
//          .portMapper()
//            .http(8080).mapsTo(8443)
//            .and()
      .authorizeHttpRequests()
      .mvcMatchers(HttpMethod.GET,"/role_user").hasAuthority("ROLE_USER")//NAME1 권한이 있는 사용자를 요구
      .mvcMatchers(HttpMethod.GET,"/role_admin").hasRole("ADMIN") //"ROLE_" 접두사를 자동으로 적용시켜주기위한 hasRole() 메소드 적용
      .antMatchers("/deny*").denyAll()
      .anyRequest().permitAll()//ant 패턴 사용가능
      .and()
      .formLogin()
//          .loginPage("/login1")//커스텀 로그인 페이지 추가
        .permitAll()//접근 권한 설정
        .defaultSuccessUrl("/home")
        .failureUrl("/fail")
        .and()
      .logout()
        .permitAll()
        .logoutSuccessUrl("/home");//이 url을 설정하지 않으면 로그인 페이지로 자동 리디렉션 되었다.





//    http.httpBasic()
//      .disable();
//      .authenticationEntryPoint(authenticationEntryPoint());

//    http
//      .requiresChannel()
//        .antMatchers("/sec/**")
//          .requiresSecure();
    /*
    * 세션 고정 보호 관련 설정부분
    * */
//    http
//      .sessionManagement()
//      .sessionFixation()
//      .none();
    /*
     * CSRF(Cross-Site Request Forgery) 사이트 간 요청 위조 방지하기
     * 스프링 시큐리티 3.2 부터 CSRF 보안은 기본 설정으로 활성화되어 있어
     * CSRF 보호를 위한 조취를 취하지 않으면 애플리케이션에 제출되는 폼을 성공적으로 얻어 오는데 문제가 발생한다.
     * (애플리케이션의 모든 폼은 반드시 _csrf 필드를 제출해야 한다는 의미)
     *
     * JSP : <input type="hidden" name="${_csrf.paremeterName }" value="${_csrf.token }"/> 태그를 추가하거나
     * 스프링 폼 바인딩 태그 라이브러리를 사용한다면 <sf:form> ~ </sf:form> 태그는 자동으로 숨겨진 CSRF 토큰 태그를 붙여준다.
    */
//    http
//      .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
//        .accessDeniedPage("/fail");
//      .accessDeniedHandler()

  }


  /**
   * 테스트를 위해 inMemoryAuthentication()에 사용자를 추가
   * [1] Password Encoder 를 적용하지 않아서 에러가 발생하고 있음. 스프링에서는 임시로 해결 가이드를 안내하고있음(권장하지 않음)
   * @link https://spring.io/blog/2017/11/01/spring-security-5-0-0-rc1-released
   *
   */
//  @Override
//  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//    auth.inMemoryAuthentication()
////      .passwordEncoder(NoOpPasswordEncoder.getInstance())// [1]
//      .passwordEncoder(passwordEncoder())
//      .withUser("user1").password("1").roles("USER");
//  }

  @Bean
  public CustomBasicAuthenticationEntryPoint authenticationEntryPoint() {
    return new CustomBasicAuthenticationEntryPoint();
  }

  @Bean
  public BCryptPasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }

//  @Bean
//  public DaoAuthenticationProvider authenticationProvider() {
//    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//    authenticationProvider.setUserDetailsService(userDetailsService);
//    authenticationProvider.setPasswordEncoder(passwordEncoder());
//
//    return authenticationProvider;
//  }




}

