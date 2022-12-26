//package com.vbot.mgmt.configs;
//import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
//import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
//import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
//import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
//import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
//import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter; 
//import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.config.ConfigurableBeanFactory;
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Scope;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
//import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
//import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
////https://www.jianshu.com/p/45040e2fe291
//
//@KeycloakConfiguration
//public class CustomKeycloakSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
//
//    private final KeycloakClientRequestFactory keycloakClientRequestFactory;
//
//    public CustomKeycloakSecurityConfig(KeycloakClientRequestFactory keycloakClientRequestFactory) {
//        this.keycloakClientRequestFactory = keycloakClientRequestFactory;
//        //By default, SecurityContextHolder uses MODE_THREADLOCAL to store the user authentication info. As a result, this info is not accessible to methods outside the current execution thread.
//        //to use principal and authentication together with @async
//        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
//    }
//
////    @Bean
////    public GrantedAuthorityDefaults grantedAuthorityDefaults() {
////        return new GrantedAuthorityDefaults(""); // Remove the ROLE_ prefix
////    }
//    @Bean
//    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
//    public KeycloakRestTemplate keycloakRestTemplate() {
//        return new KeycloakRestTemplate(keycloakClientRequestFactory);
//    }
////    Authority represents an individual permission.  @PreAuthorize(“hasAuthority(‘EDIT_BOOK’)”)
////    Role represents a group of permissions.  @PreAuthorize(“hasRole(‘BOOK_ADMIN’)”)
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
//        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
//        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
//        authenticationManagerBuilder.authenticationProvider(keycloakAuthenticationProvider);
//    }
//
//    @Bean
//    @Override
//    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
//        return new NullAuthenticatedSessionStrategy();
//    }
//
//    @Override
//    protected void configure(HttpSecurity httpSecurity) throws Exception    {
//        super.configure(httpSecurity);
//        httpSecurity.cors().and().csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
//                .and()
//                .authorizeRequests()
//                .antMatchers("/unsecured-v1").permitAll()
//                .antMatchers("/user-v1").hasRole("USER")
//                .antMatchers("/admin-v1").hasRole("ADMIN")
//                .antMatchers("/all-user-v1").hasAnyRole("USER", "ADMIN")
//                .anyRequest().permitAll(); //.anyRequest().authenticated();//.anyRequest().denyAll();// .anyRequest().fullyAuthenticated();
//    }
//
//    @Bean
//    public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(KeycloakAuthenticationProcessingFilter filter) {
//        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean(filter);
//        filterRegistrationBean.setEnabled(false);
//        return filterRegistrationBean;
//    }
//
//    @Bean
//    public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(KeycloakPreAuthActionsFilter filter) {
//        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean(filter);
//        filterRegistrationBean.setEnabled(false);
//        return filterRegistrationBean;
//    }
//}
//
//
//
////        Role                                               Permissions
////        ###         Add a product	View all products	View product	Update product	Delete product
////        Intern	      Yes	             Yes	             -	                -	           -
////        Supervisor	  Yes	             Yes	            Yes	                -`	           -
////        Admin	          Yes	             Yes	            Yes	               Yes	          Yes
//
////        .antMatchers(HttpMethod.DELETE, "/api/v1/products/{productId}").hasRole(ADMIN.name()) // Admin should be able to delete
////        .antMatchers(HttpMethod.PUT, "/api/v1/products/{productId}").hasRole(ADMIN.name()) // Admin should be able to update
////        .antMatchers("/api/v1/products/add").hasAnyRole(ADMIN.name(), SUPERVISOR.name()) // Admin and Supervisor should be able to add product.
////        .antMatchers("/api/v1/products").hasAnyRole(ADMIN.name(), SUPERVISOR.name(), INTERN.name()) // All three users should be able to get all products.
////        .antMatchers("/api/v1/products{productId}").hasAnyRole(ADMIN.name(), SUPERVISOR.name(), INTERN.name()) // All three users should be able to get a product by id.