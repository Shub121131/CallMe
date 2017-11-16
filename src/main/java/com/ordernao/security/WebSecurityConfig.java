package com.ordernao.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.ordernao.utility.OrderNaoConstants;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private DataSource dataSource;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		/*.antMatchers(OrderNaoConstants.CALL_OPERATOR_LINKS).hasRole("CALLOPERATOR")
		.antMatchers(OrderNaoConstants.MANAGER_LINKS).hasRole("MANAGER")
		.antMatchers(OrderNaoConstants.DELIVERY_BOY_LINKS).hasRole("DELIVERYBOY")*/
		.antMatchers("/").permitAll()
		.antMatchers("/login").permitAll()
		.antMatchers("/**").hasRole("ADMIN").and()
		.formLogin().loginPage("/login").usernameParameter("username").passwordParameter("password").defaultSuccessUrl(OrderNaoConstants.PATH_HOMEPAGE).and()
		.logout().logoutUrl("/logout")
		.logoutSuccessUrl("/login?logout");
		// Disable csrf for now
		http.csrf().disable();
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource)
				.usersByUsernameQuery("select email as username,password,true as enabled from users where email = ?")
				.authoritiesByUsernameQuery(
						"select email as username,concat(\"ROLE_\",role_name) as role from users inner join roles on users.roleid = roles.role_id where email = ?");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources/**", "/js/**", "/css/**", "/images/**"); // #3
	}
}