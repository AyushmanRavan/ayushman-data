//package com.vbot.mgmt.configs;
//
//import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
//import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
//import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
//import org.springframework.context.annotation.Bean;
//import org.springframework.core.Ordered;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
//import org.springframework.http.HttpMethod;
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
//import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
//import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
//import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//import org.springframework.web.filter.CorsFilter;
//
//import java.util.Arrays;
//import java.util.Collections;
//
//@KeycloakConfiguration
//public class TempData extends KeycloakWebSecurityConfigurerAdapter { //2
//
// 
////    @Bean
////    public GrantedAuthorityDefaults getGrantedAuthorityDefaults() {
////        return new GrantedAuthorityDefaults(""); // Remove the ROLE_ prefix
////    }
//
//    @Bean
//    public GrantedAuthoritiesMapper getGrantedAuthoritiesMapper() {
//        SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
//        return simpleAuthorityMapper;
//    }
//
//    @Override
//    protected KeycloakAuthenticationProvider keycloakAuthenticationProvider() {
//        KeycloakAuthenticationProvider keycloakAuthenticationProvider = super.keycloakAuthenticationProvider();
//        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(getGrantedAuthoritiesMapper());
//        return keycloakAuthenticationProvider;
//    }
//
//    @Override
//    protected void configure(final AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
//        authenticationManagerBuilder.authenticationProvider(keycloakAuthenticationProvider());
//    }
//
//    @Override
//    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() { //6
//        // return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl()); // RegisterSessionAuthenticationStrategy for public or confidential applications
//        return new NullAuthenticatedSessionStrategy(); // NullAuthenticatedSessionStrategy for bearer-only applications.
//    }
//
//    @Override
//    protected void configure(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity
////               .cors().and().csrf().disable()  // disable csrf because of API mode
//                .sessionManagement()
//                // use previously declared bean
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
//                .and()
//                .authorizeRequests()  // manage routes securisation here
//                .antMatchers(HttpMethod.OPTIONS).permitAll()
//                .antMatchers("/unsecured-v1").permitAll()
//                .antMatchers("/user-v1").hasRole("USER")
//                .antMatchers("/admin-v1").hasRole("ADMIN")
//                .antMatchers("/all-user-v1").hasAnyRole("USER", "ADMIN")
////        .anyRequest().authenticated(); //   .anyRequest().permitAll();
//                .anyRequest().denyAll();
//
//    }
//
//    @Bean
//    public FilterRegistrationBean<CorsFilter> corsFilter() {
//
//        CorsConfiguration config = new CorsConfiguration();
//        config.setAllowCredentials(true);
//        config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:4200"));
//        config.setAllowedMethods(Collections.singletonList("*")); // "GET","POST","PATCH", "PUT", "DELETE", "OPTIONS", "HEAD"
//        config.setAllowedHeaders(Collections.singletonList("*")); // "Authorization", "Cache-Control", "Content-Type"
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", config);
//
//        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
//        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
//        return bean;
//    }
//// Here are two HTTP header messages that determine if a request is allowed or blocked:
//// Access-Control-Allow-Credentials: true, Access-Control-Allow-Origin
//
////    @Bean
////    public FilterRegistrationBean
////    keycloakAuthenticationProcessingFilterRegistrationBean(KeycloakAuthenticationProcessingFilter filter) {
////        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
////        registrationBean.setEnabled(false);
////        return registrationBean;
////    }
////
////    @Bean
////    public FilterRegistrationBean
////    keycloakPreAuthActionsFilterRegistrationBean(KeycloakPreAuthActionsFilter filter) {
////        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
////        registrationBean.setEnabled(false);
////        return registrationBean;
////    }
//}
//
//
////    @Bean
////    public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
////            final KeycloakAuthenticationProcessingFilter filter) {
////        final FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
////        registrationBean.setEnabled(false);
////        return registrationBean;
////    }
////
////    @Bean
////    public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
////            final KeycloakPreAuthActionsFilter filter) {
////        final FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
////        registrationBean.setEnabled(false);
////        return registrationBean;
////    }
//
//
////
////    @Autowired
////    public void configureGlobal(AuthenticationManagerBuilder authenticationManagerBuilder) { //4
////        authenticationManagerBuilder.authenticationProvider(keycloakAuthenticationProvider());
////    }
//
//
////    private KeycloakAuthenticationProvider getKeycloakAuthenticationProvider() { //5
////        KeycloakAuthenticationProvider authenticationProvider = keycloakAuthenticationProvider();
////        SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();// simple Authority Mapper to avoid ROLE_
////        simpleAuthorityMapper.setConvertToUpperCase(true);
//////      simpleAuthorityMapper.setPrefix("ROLE_");
//////      simpleAuthorityMapper.setPrefix("");
////        authenticationProvider.setGrantedAuthoritiesMapper(simpleAuthorityMapper);
////        return authenticationProvider;
////    }
//
//
////    @Override
////    protected void configure(HttpSecurity http) throws Exception {
////        super.configure(http);
////        http.csrf().disable()
////                .formLogin().disable()
////                .sessionManagement()
////                // use previously declared bean
////                .sessionAuthenticationStrategy(sessionAuthenticationStrategy()).and()
////                .authorizeRequests()
//////                manage routes security here.
////                  .antMatchers ("/api/unsecured").permitAll()
////                  .antMatchers("/api/user").hasAnyRole("USER") // .antMatchers("/user").hasRole ("USER")
////                  .antMatchers("/api/admin").hasAnyRole("ADMIN")
////                  .antMatchers("/api/all-user").hasAnyRole("USER","ADMIN")
//////                .anyRequest().permitAll();
////                .anyRequest().denyAll() ;
//////                .anyRequest().authenticated();
//////        http.csrf().disable(); // disable csrf because of API mode
//////        http.cors().disable();
//////      http.formLogin().disable();
////    }
//
//
////    @Override
////    protected void configure(HttpSecurity http) throws Exception {
////        super.configure(http);
////        http.authorizeRequests()
////                .antMatchers("/public/**").permitAll()
////                .antMatchers("/member/**").hasAnyRole("member")
////                .antMatchers("/moderator/**").hasAnyRole("moderator")
////                .antMatchers("/admin/**").hasAnyRole("admin")
////                .anyRequest()
////                .permitAll();
////        http.csrf().disable();
////    }
//
//
////    @Override
////    protected void configure(HttpSecurity http) throws Exception {
////        super.configure(http);
////        http.cors().and().csrf().disable().sessionManagement().
////                sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
////                authorizeRequests()
////                .antMatchers("/employees/unprotected").permitAll()
////                .antMatchers("/employees/create").permitAll()
////                .antMatchers("/employees/login").permitAll()
////                .anyRequest().authenticated();
////    }
//
//
////@Configuration
////@EnableWebSecurity
////@EnableGlobalMethodSecurity(jsr250Enabled = true)
//
////@Configuration
////@EnableWebSecurity
////@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
////@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
//
//
////@Configuration + @EnableWebSecurity + @ComponentScan(basePackageClasses = KeycloakSecurityComponents.class) = @KeycloakConfiguration
//
//
////    @Override
////    protected void configure(HttpSecurity http) throws Exception {
////        super.configure(http);
////
////        http.cors().and().csrf().disable().sessionManagement().
////
////                sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests()
////                .antMatchers("/users/unprotected-data").permitAll()
////                .antMatchers("/users/create").permitAll()
////                .antMatchers("/users/signin").permitAll()
////                .anyRequest().authenticated();
////
////    }
//
//
////    @Autowired
////    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
////        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
////        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
////        auth.authenticationProvider(keycloakAuthenticationProvider);
////    }
//
//
////    @Override
////    protected void configure(HttpSecurity http) throws Exception { //3
////        super.configure(http);
////        http
////                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////                .and()
////                .authorizeRequests()
////                .anyRequest().permitAll();
////
//////        .authorizeRequests()
//////        .anyRequest().authenticated();
////    }
//
////    @Override
////    protected void configure(HttpSecurity http) throws Exception {
////        super.configure(http);
////        http.cors().and().csrf().disable().sessionManagement().
////                sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
////                authorizeRequests()
////                .antMatchers("/employees/unprotected").permitAll()
////                .antMatchers("/employees/create").permitAll()
////                .antMatchers("/employees/login").permitAll()
////                .anyRequest().authenticated();
////    }
//
//
////    @Override
////    protected void configure(HttpSecurity http) throws Exception {
////        super.configure(http);
////        http
////                .headers().frameOptions().sameOrigin()
////                .and()
////                .csrf().disable()
////                .authorizeRequests()
////                .antMatchers(HttpMethod.POST, "/quotes*").hasRole("admin") //only this is not public
////                .anyRequest().permitAll();
////    }



// Client for Spring Boot app with actuator endpoints in Keycloak
//Client-Protocol: OpenID Connect
// Access-Type: confidential
// Standard-Flow Enabled: on
// Direct-Access grants: off
//
// Root URL: http://localhost:30002
// Valid redirect URIs: /*
//Base URL: /
//Admin URL: /
//Web Origins: *



//Confidential access-type indicates, that we will need a secret to authenticate this client against the Keycloak server
//service accounts enabled set to ON allows us to generate a token dedicated to this client.

//Client for Spring Boot Admin in Keycloak
//Client-Protocol: OpenID Connect
//Access-Type: confidential
//Standard-Flow Enabled: on
//Direct-Access grants: off
//Service-Accounts Enabled: on
//Authorization Enabled: on
//Root URL: http://localhost:30001
//Valid redirect URIs: /*
//Base URL: /admin
//Admin URL: /
//Web Origins: *