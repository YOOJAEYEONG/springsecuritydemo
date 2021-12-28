package com.security.springsecuritydemo.preset;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;


/**
 * 스프링 앱 구동시 H2 DB 에 자동 실행할 쿼리를위해 추가함.
 */
@Component
@RequiredArgsConstructor
public class H2Runner implements ApplicationRunner {

  final DataSource dataSource;

  //JdbcTemplate도 사용가능
  final JdbcTemplate jdbcTemplate;

  @Override
  public void run(ApplicationArguments args) throws Exception {
    try(Connection connection = dataSource.getConnection()) {

      Statement statement = connection.createStatement();
      String ddl = "CREATE TABLE USERS ( NAME NVARCHAR2 PRIMARY KEY, PASSWORD NVARCHAR2, ROLE NVARCHAR2)";
      statement.executeUpdate(ddl);
      String dml_insert1 = "INSERT INTO USERS VALUES('user', '1', 'ROLE_ADMIN');";
      statement.executeUpdate(dml_insert1);
      String dml_insert2 = "INSERT INTO USERS VALUES('user1', '1', 'ROLE_USER');";
      statement.executeUpdate(dml_insert2);
      String dml_select = "SELECT * FROM USERS;";
      ResultSet rs = statement.executeQuery(dml_select);

      while (rs.next()){
        String name = rs.getNString("name");
        String role = rs.getNString("role");
        System.out.println("USERINFO > name : "+name+"\trole : "+role);
      }
      connection.close();
    }
  }
}
