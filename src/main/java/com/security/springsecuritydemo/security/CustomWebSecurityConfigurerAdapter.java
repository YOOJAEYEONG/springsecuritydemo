package com.security.springsecuritydemo.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

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
      .formLogin()
        .loginPage("/login1")//커스텀 로그인 페이지 추가
        .permitAll()//접근 권한 설정
        .and()
      .logout().permitAll()
        .and()
      .authorizeHttpRequests()
        .mvcMatchers("/").permitAll()
        .mvcMatchers(HttpMethod.GET,"/url1","/url2")
          .hasAuthority("ROLE_NAME1")//NAME1 권한이 있는 사용자를 요구
        .mvcMatchers(HttpMethod.GET,"/url3")
          .hasRole("USER") //"ROLE_" 접두사를 자동으로 적용시켜주기위한 hasRole() 메소드 적용
        .antMatchers("/url4/**").denyAll()//ant 패턴 사용가능
//        .anyRequest()//matchers 로 지정한 경로를 제외 모든 요청에 해당함
//          .authenticated()//인가가 필요한 조건으로 설정함
        .and()
      .httpBasic().authenticationEntryPoint(authenticationEntryPoint())
        .and()
      /*
      *  선택한 URL에 HTTPS를 적용 :
      *  안전한 채널이 요구하는지 확인하고 자동적으로 요청을 HTTPS로 리다이렉션 시켜준다.
      * */
      .requiresChannel()
        .antMatchers("/sec/**","/login*","/login1","login1")
          .requiresSecure()
        .and()
//      .cors().disable().csrf().disable()
      /*
      * 세션 고정 보호 관련 설정부분
      * */
      .sessionManagement()
        .sessionFixation()
        .none()
//      .requiresChannel()
//        .mvcMatchers("/","login1")
//          .requiresInsecure()
      /*
       * CSRF(Cross-Site Request Forgery) 사이트 간 요청 위조 방지하기
       * 스프링 시큐리티 3.2 부터 CSRF 보안은 기본 설정으로 활성화되어 있어
       * CSRF 보호를 위한 조취를 취하지 않으면 애플리케이션에 제출되는 폼을 성공적으로 얻어 오는데 문제가 발생한다.
       * (애플리케이션의 모든 폼은 반드시 _csrf 필드를 제출해야 한다는 의미)
       *
       * JSP : <input type="hidden" name="${_csrf.paremeterName }" value="${_csrf.token }"/> 태그를 추가하거나
       * 스프링 폼 바인딩 태그 라이브러리를 사용한다면 <sf:form> ~ </sf:form> 태그는 자동으로 숨겨진 CSRF 토큰 태그를 붙여준다.
      */
//      .csrf().disable()
        .and()
      .csrf().disable().cors().disable()
        .sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
      .exceptionHandling()
        .accessDeniedPage("/accessDeniedPage")
//      .accessDeniedHandler()
    ;
  }

  @Bean
  public CustomBasicAuthenticationEntryPoint authenticationEntryPoint() {
    return new CustomBasicAuthenticationEntryPoint();
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

