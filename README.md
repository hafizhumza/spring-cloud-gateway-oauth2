# spring-cloud-gateway-oauth2

## Preface
Our ideal microservice permission solution should be like this, the authentication service is responsible for authentication, the gateway is responsible for verification and authentication, and other API services are responsible for processing their own business logic. Security-related logic only exists in authentication services and gateway services, and other services simply provide services without any security-related logic.
## Architecture
Unified authentication is performed through the authentication service (`oauth2-auth`), and then the gateway (`oauth2-gateway`) is used to uniformly verify the authentication and authentication. Use Nacos as the registry, Gateway as the gateway, and use the nimbus-jose-jwtJWT library to operate JWT tokens.
- oauth2-auth: Oauth2 authentication service, responsible for authenticating logged in users, integrating Spring Security Oauth2
- ouath2-gateway: gateway service, responsible for request forwarding and authentication functions, integrating Spring Security Oauth2
- oauth2-resource: protected API service, which can be accessed after user authentication passes, does not integrate Spring Security Oauth2
## Implementation
### 1. Authentication service `oauth2-auth`

> 1. First, build the authentication service, which will be used as the authentication service of Oauth2, and the authentication function of the gateway service also needs to rely on it. Add related dependencies in pom.xml, mainly Spring Security, Oauth2, JWT, Redis related dependencies

```java
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-oauth2</artifactId>
    </dependency>
    <dependency>
        <groupId>com.nimbusds</groupId>
        <artifactId>nimbus-jose-jwt</artifactId>
        <version>8.16</version>
    </dependency>
    <!-- redis -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
</dependencies>

```

> 2. Add related configurations in application.yml, mainly Nacos and Redis related configurations

```yml
server:
  port: 9401
spring:
  profiles:
    active: dev
  application:
    name: oauth2-auth
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
  jackson:
    date-format: yyyy-MM-dd HH:mm:ss
  redis:
    database: 0
    port: 6379
    host: localhost
    password:
management:
  endpoints:
    web:
      exposure:
        include: "*"

```

> 3. Use keytool to generate the RSA certificate jwt.jks, copy it to the resource directory, and use the following command in the JDK bin directory

```shell
keytool -genkey -alias jwt -keyalg RSA -keystore jwt.jks
```

> 4. Create a UserServiceImpl class to implement Spring Security's UserDetailsService interface for loading user information

```Java
package cn.gathub.auth.service.impl;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import cn.gathub.auth.constant.MessageConstant;
import cn.gathub.auth.domain.entity.User;
import cn.gathub.auth.service.UserService;
import cn.gathub.auth.service.principal.UserPrincipal;
import cn.hutool.core.collection.CollUtil;

/**
 * User management business class
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@Service
public class UserServiceImpl implements UserService {

  private List<User> userList;
  private final PasswordEncoder passwordEncoder;

  public UserServiceImpl(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @PostConstruct
  public void initData() {
    String password = passwordEncoder.encode("123456");
    userList = new ArrayList<>();
    userList.add(new User(1L, "admin", password, 1, CollUtil.toList("ADMIN")));
    userList.add(new User(2L, "user", password, 1, CollUtil.toList("USER")));
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    List<User> findUserList = userList.stream().filter(item -> item.getUsername().equals(username)).collect(Collectors.toList());
    if (CollUtil.isEmpty(findUserList)) {
      throw new UsernameNotFoundException(MessageConstant.USERNAME_PASSWORD_ERROR);
    }
    UserPrincipal userPrincipal = new UserPrincipal(findUserList.get(0));
    if (!userPrincipal.isEnabled()) {
      throw new DisabledException(MessageConstant.ACCOUNT_DISABLED);
    } else if (!userPrincipal.isAccountNonLocked()) {
      throw new LockedException(MessageConstant.ACCOUNT_LOCKED);
    } else if (!userPrincipal.isAccountNonExpired()) {
      throw new AccountExpiredException(MessageConstant.ACCOUNT_EXPIRED);
    } else if (!userPrincipal.isCredentialsNonExpired()) {
      throw new CredentialsExpiredException(MessageConstant.CREDENTIALS_EXPIRED);
    }
    return userPrincipal;
  }

}

```

> 5. Create a ClientServiceImpl class to implement Spring Security's ClientDetailsService interface for loading client information

```java
package cn.gathub.auth.service.impl;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import cn.gathub.auth.constant.MessageConstant;
import cn.gathub.auth.domain.entity.Client;
import cn.gathub.auth.service.ClientService;
import cn.gathub.auth.service.principal.ClientPrincipal;
import cn.hutool.core.collection.CollUtil;

/**
 * Client management business class
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/18
 */
@Service
public class ClientServiceImpl implements ClientService {

  private List<Client> clientList;
  private final PasswordEncoder passwordEncoder;

  public ClientServiceImpl(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @PostConstruct
  public void initData() {
    String clientSecret = passwordEncoder.encode("123456");
    clientList = new ArrayList<>();
    // 1. Password mode
    clientList.add(Client.builder()
        .clientId("client-app")
        .resourceIds("oauth2-resource")
        .secretRequire(false)
        .clientSecret(clientSecret)
        .scopeRequire(false)
        .scope("all")
        .authorizedGrantTypes("password,refresh_token")
        .authorities("ADMIN,USER")
        .accessTokenValidity(3600)
        .refreshTokenValidity(86400).build());
    // 2. Authorization code mode
    clientList.add(Client.builder()
        .clientId("client-app-2")
        .resourceIds("oauth2-resource2")
        .secretRequire(false)
        .clientSecret(clientSecret)
        .scopeRequire(false)
        .scope("all")
        .authorizedGrantTypes("authorization_code,refresh_token")
        .webServerRedirectUri("https://www.gathub.cn,https://www.baidu.com")
        .authorities("USER")
        .accessTokenValidity(3600)
        .refreshTokenValidity(86400).build());
  }

  @Override
  public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
    List<Client> findClientList = clientList.stream().filter(item -> item.getClientId().equals(clientId)).collect(Collectors.toList());
    if (CollUtil.isEmpty(findClientList)) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, MessageConstant.NOT_FOUND_CLIENT);
    }
    return new ClientPrincipal(findClientList.get(0));
  }
}

```

> 6. Add the Oauth2ServerConfig configuration related to the authentication service. You need to configure the service UserServiceImpl that loads user information the service ClientServiceImpl that loads client information, and the key pair of RSA KeyPair

```java
package cn.gathub.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import cn.gathub.auth.component.JwtTokenEnhancer;
import cn.gathub.auth.service.ClientService;
import cn.gathub.auth.service.UserService;
import lombok.AllArgsConstructor;

/**
 * Authentication server configuration
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@AllArgsConstructor
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

  private final UserService userService;
  private final ClientService clientService;
  private final AuthenticationManager authenticationManager;
  private final JwtTokenEnhancer jwtTokenEnhancer;

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//    clients.inMemory()
//        // 1. Password mode
//        .withClient("client-app")
//        .secret(passwordEncoder.encode("123456"))
//        .scopes("read,write")
//        .authorizedGrantTypes("password", "refresh_token")
//        .accessTokenValiditySeconds(3600)
//        .refreshTokenValiditySeconds(86400)
//        .and()
//        // 2. Authorization code authorization
//        .withClient("client-app-2")
//        .secret(passwordEncoder.encode("123456"))
//        .scopes("read")
//        .authorizedGrantTypes("authorization_code", "refresh_token")
//        .accessTokenValiditySeconds(3600)
//        .refreshTokenValiditySeconds(86400)
//        .redirectUris("https://www.gathub.cn", "https://www.baidu.com");
    clients.withClientDetails(clientService);
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
    TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
    List<TokenEnhancer> delegates = new ArrayList<>();
    delegates.add(jwtTokenEnhancer);
    delegates.add(accessTokenConverter());
    enhancerChain.setTokenEnhancers(delegates); //Configuring Content Enhancer for JWT
    endpoints.authenticationManager(authenticationManager)
        .userDetailsService(userService) //Configure a service that loads user information
        .accessTokenConverter(accessTokenConverter())
        .tokenEnhancer(enhancerChain);
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) {
    security.allowFormAuthenticationForClients();
  }

  @Bean
  public JwtAccessTokenConverter accessTokenConverter() {
    JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    jwtAccessTokenConverter.setKeyPair(keyPair());
    return jwtAccessTokenConverter;
  }

  @Bean
  public KeyPair keyPair() {
    // Get the key pair from the certificate on the classpath
    KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "654321".toCharArray());
    return keyStoreKeyFactory.getKeyPair("jwt", "654321".toCharArray());
  }

}

```

> 7. If you want to add custom information to the JWT, such as the ID of the logged in user, you can implement the TokenEnhancer interface yourself

```java
package cn.gathub.auth.component;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

import cn.gathub.auth.service.principal.UserPrincipal;


/**
 * JWT Content Enhancer
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@Component
public class JwtTokenEnhancer implements TokenEnhancer {
  @Override
  public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
    UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
    Map<String, Object> info = new HashMap<>();
    // Set the user ID into the JWT
    info.put("id", userPrincipal.getId());
    ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
    return accessToken;
  }
}

```

> 8. Since our gateway service needs the public key of RSA to verify whether the signature is legal, the authentication service needs to have an interface to expose the public key

```java
package cn.gathub.auth.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 * Get RSA public key interface
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@RestController
public class KeyPairController {

  private final KeyPair keyPair;

  public KeyPairController(KeyPair keyPair) {
    this.keyPair = keyPair;
  }

  @GetMapping("/rsa/publicKey")
  public Map<String, Object> getKey() {
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAKey key = new RSAKey.Builder(publicKey).build();
    return new JWKSet(key).toJSONObject();
  }

}

```

> 9. You also need to configure Spring Security to allow access to the public key interface

```java
package cn.gathub.auth.config;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * SpringSecurity configuration
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
        .antMatchers("/rsa/publicKey").permitAll()
        .anyRequest().authenticated();
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

}

```

> 10. Create a resource service ResourceServiceImpl, and cache the resource and role matching relationship in Redis during initialization, which is convenient for the gateway service to obtain during authentication

```java
package cn.gathub.auth.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.annotation.PostConstruct;

import cn.gathub.auth.constant.RedisConstant;
import cn.hutool.core.collection.CollUtil;

/**
 * Resource and role matching relationship management business class
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@Service
public class ResourceServiceImpl {

  private final RedisTemplate<String, Object> redisTemplate;

  public ResourceServiceImpl(RedisTemplate<String, Object> redisTemplate) {
    this.redisTemplate = redisTemplate;
  }

  @PostConstruct
  public void initData() {
    Map<String, List<String>> resourceRolesMap = new TreeMap<>();
    resourceRolesMap.put("/resource/hello", CollUtil.toList("ADMIN"));
    resourceRolesMap.put("/resource/user/currentUser", CollUtil.toList("ADMIN", "USER"));
    redisTemplate.opsForHash().putAll(RedisConstant.RESOURCE_ROLES_MAP, resourceRolesMap);
  }
}

```

### 2. Gateway service `oauth2-gateway`
Next, build a gateway service, which will be used as a resource service and client service of Oauth2 to perform unified verification, authentication and authentication operations on requests to access microservices

> 1. Add related dependencies in pom.xml, mainly Gateway, Oauth2 and JWT related dependencies

```java
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-webflux</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-gateway</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-config</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-oauth2-resource-server</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-oauth2-client</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-oauth2-jose</artifactId>
    </dependency>
    <dependency>
        <groupId>com.nimbusds</groupId>
        <artifactId>nimbus-jose-jwt</artifactId>
        <version>8.16</version>
    </dependency>
</dependencies>

```

> 2. Add relevant configuration in application.yml, mainly the configuration of routing rules, the configuration of RSA public key in Oauth2, and the configuration of routing whitelist

```yml
server:
  port: 9201
spring:
  profiles:
    active: dev
  application:
    name: oauth2-gateway
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
    gateway:
      routes: # Configure routing paths
        - id: oauth2-resource-route
          uri: lb://oauth2-resource
          predicates:
            - Path=/resource/**
          filters:
            - StripPrefix=1
        - id: oauth2-auth-route
          uri: lb://oauth2-auth
          predicates:
            - Path=/auth/**
          filters:
            - StripPrefix=1
        - id: oauth2-auth-login
          uri: lb://oauth2-auth
          predicates:
            - Path=/login
          filters:
            - PreserveHostHeader
        - id: oauth2-auth-token
          uri: lb://oauth2-auth
          predicates:
            - Path=/oauth/token
          filters:
            - PreserveHostHeader
        - id: oauth2-auth-authorize
          uri: lb://oauth2-auth
          predicates:
            - Path=/oauth/authorize
          filters:
            - PreserveHostHeader
      discovery:
        locator:
          enabled: true # Enable the function of dynamically creating routes from the registry
          lower-case-service-id: true # Use lowercase service name, default is uppercase
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: 'http://localhost:9401/rsa/publicKey' # Configure the public key access address of RSA
  redis:
    database: 0
    port: 6379
    host: localhost
    password:
secure:
  ignore:
    urls: # Configure the whitelist path
      - "/actuator/**"
      - "/oauth/token"
      - "/oauth/authorize"
      - "/login"

```

> 3. Configure the security configuration for the gateway service. Since the Gateway uses WebFlux, you need to use the @EnableWebFluxSecurity annotation to enable it

```java
package cn.gathub.gateway.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import cn.gathub.gateway.authorization.AuthorizationManager;
import cn.gathub.gateway.component.RestAuthenticationEntryPoint;
import cn.gathub.gateway.component.RestfulAccessDeniedHandler;
import cn.gathub.gateway.constant.AuthConstant;
import cn.gathub.gateway.filter.IgnoreUrlsRemoveJwtFilter;
import cn.hutool.core.util.ArrayUtil;
import lombok.AllArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * Resource server configuration
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@AllArgsConstructor
@Configuration
@EnableWebFluxSecurity
public class ResourceServerConfig {
  private final AuthorizationManager authorizationManager;
  private final IgnoreUrlsConfig ignoreUrlsConfig;
  private final RestfulAccessDeniedHandler restfulAccessDeniedHandler;
  private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;
  private final IgnoreUrlsRemoveJwtFilter ignoreUrlsRemoveJwtFilter;

  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter());
    // 1. Customize the result of processing JWT request header expiration or signature error
    http.oauth2ResourceServer().authenticationEntryPoint(restAuthenticationEntryPoint);
    // 2. For the whitelist path, directly remove the JWT request header
    http.addFilterBefore(ignoreUrlsRemoveJwtFilter, SecurityWebFiltersOrder.AUTHENTICATION);
    http.authorizeExchange()
        .pathMatchers(ArrayUtil.toArray(ignoreUrlsConfig.getUrls(), String.class)).permitAll() // Whitelist configuration
        .anyExchange().access(authorizationManager) // Authentication Manager Configuration
        .and().exceptionHandling()
        .accessDeniedHandler(restfulAccessDeniedHandler) // Handling unauthorized
        .authenticationEntryPoint(restAuthenticationEntryPoint) // Handling unauthenticated
        .and().csrf().disable();
    return http.build();
  }

  @Bean
  public Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    jwtGrantedAuthoritiesConverter.setAuthorityPrefix(AuthConstant.AUTHORITY_PREFIX);
    jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(AuthConstant.AUTHORITY_CLAIM_NAME);
    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
    return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
  }

}

```
> 4. Custom authentication operations in WebFluxSecurity need to implement the ReactiveAuthorizationManager interface

```java
package cn.gathub.gateway.authorization;


import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

import cn.gathub.gateway.constant.AuthConstant;
import cn.gathub.gateway.constant.RedisConstant;
import cn.hutool.core.convert.Convert;
import reactor.core.publisher.Mono;

/**
 * Authentication manager, used to determine whether there is access to resources
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@Component
public class AuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {
  private final RedisTemplate<String, Object> redisTemplate;

  public AuthorizationManager(RedisTemplate<String, Object> redisTemplate) {
    this.redisTemplate = redisTemplate;
  }

  @Override
  public Mono<AuthorizationDecision> check(Mono<Authentication> mono, AuthorizationContext authorizationContext) {
    // 1. Get the list of accessible roles from the current path from Redis
    URI uri = authorizationContext.getExchange().getRequest().getURI();
    Object obj = redisTemplate.opsForHash().get(RedisConstant.RESOURCE_ROLES_MAP, uri.getPath());
    List<String> authorities = Convert.toList(String.class, obj);
    authorities = authorities.stream().map(i -> i = AuthConstant.AUTHORITY_PREFIX + i).collect(Collectors.toList());
    // 2. Users who pass the authentication and match the roles can access the current path
    return mono
        .filter(Authentication::isAuthenticated)
        .flatMapIterable(Authentication::getAuthorities)
        .map(GrantedAuthority::getAuthority)
        .any(authorities::contains)
        .map(AuthorizationDecision::new)
        .defaultIfEmpty(new AuthorizationDecision(false));
  }

}

```

> 5. Here we also need to implement a global filter AuthGlobalFilter. After the authentication is passed, the user information in the JWT token is parsed, and then stored in the request header, so that subsequent services do not need to parse the JWT token, you can Get user information directly from the request header

```java
package cn.gathub.gateway.filter;

import com.nimbusds.jose.JWSObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.text.ParseException;

import cn.hutool.core.util.StrUtil;
import reactor.core.publisher.Mono;

/**
 * A global filter that converts the logged-in user's JWT into user information
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@Component
public class AuthGlobalFilter implements GlobalFilter, Ordered {

  private final static Logger LOGGER = LoggerFactory.getLogger(AuthGlobalFilter.class);

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String token = exchange.getRequest().getHeaders().getFirst("Authorization");
    if (StrUtil.isEmpty(token)) {
      return chain.filter(exchange);
    }
    try {
      // Parse the user information from the token and set it to the Header
      String realToken = token.replace("Bearer ", "");
      JWSObject jwsObject = JWSObject.parse(realToken);
      String userStr = jwsObject.getPayload().toString();
      LOGGER.info("AuthGlobalFilter.filter() user:{}", userStr);
      ServerHttpRequest request = exchange.getRequest().mutate().header("user", userStr).build();
      exchange = exchange.mutate().request(request).build();
    } catch (ParseException e) {
      e.printStackTrace();
    }
    return chain.filter(exchange);
  }

  @Override
  public int getOrder() {
    return 0;
  }
}

```

### 3. Resource service (API service) `oauth2-resource`

Finally, we build an API service, which will not integrate and implement any security-related logic, and rely on the gateway to protect it

> 1. Add related dependencies in pom.xml, and a web dependency is added

```java
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

> 2. Add relevant configuration in application.yml, which is very conventional configuration

```yml
server:
  port: 9501
spring:
  profiles:
    active: dev
  application:
    name: oauth2-resource
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
management:
  endpoints:
    web:
      exposure:
        include: "*"

```

> 3. Create a test interface, the gateway can be accessed after verification

```java
package cn.gathub.resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@RestController
public class HelloController {

  @GetMapping("/hello")
  public String hello() {
    return "Hello World !";
  }

}

```

> 4. Create an interface for obtaining the user information in the login, which is used to directly obtain the login user information from the requested Header

```java
package cn.gathub.resource.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

import cn.gathub.resource.domain.User;
import cn.hutool.core.convert.Convert;
import cn.hutool.json.JSONObject;

/**
 * Get login user information interface
 *
 * @author Honghui [wanghonghui_work@163.com] 2021/3/16
 */
@RestController
@RequestMapping("/user")
public class UserController {

  @GetMapping("/currentUser")
  public User currentUser(HttpServletRequest request) {
    // Get user information from Header
    String userStr = request.getHeader("user");
    JSONObject userJsonObject = new JSONObject(userStr);
    return User.builder()
        .username(userJsonObject.getStr("user_name"))
        .id(Convert.toLong(userJsonObject.get("id")))
        .roles(Convert.toList(String.class, userJsonObject.get("authorities"))).build();
  }
}

```

## Demo
Before that, start our Nacos and Redis services, and then start the `oauth2-auth`, `oauth2-gateway` and `oauth2-api` services in turn

The stand-alone version of Nacos that I use here to test Docker runs
```shell
docker pull nacos/nacos-server
docker run --env MODE=standalone --name nacos -d -p 8848:8848 nacos/nacos-server
```
> 1. Use the password mode to obtain the JWT token, access address: http://localhost:9201/oauth/token

![image](https://user-images.githubusercontent.com/35522446/111894792-b8583900-8a48-11eb-8206-57aeb76d25ab.png)

> 2. Use the obtained JWT token to access the interface that requires permissions, and the access address: http://localhost:9201/resource/hello

![image](https://user-images.githubusercontent.com/35522446/111894802-d4f47100-8a48-11eb-9f78-9125d27e4cb3.png)

> 3. Use the obtained JWT token to access the interface for obtaining the information of the current logged-in user. Access address: http://localhost:9201/resource/user/currentUser

![image](https://user-images.githubusercontent.com/35522446/111894819-fc4b3e00-8a48-11eb-853c-9ae1c58e4f18.png)

> 4. When the token does not exist, access the address: http://localhost:9201/resource/user/currentUser

![image](https://user-images.githubusercontent.com/35522446/111894829-108f3b00-8a49-11eb-8460-cd936b7b15f3.png)

> 5. When the JWT token expires, use refresh_token to obtain a new JWT token, access address: http://localhost:9201/oauth/token

![image](https://user-images.githubusercontent.com/35522446/111894845-30befa00-8a49-11eb-8e35-878dada90401.png)

> 6. When using the authorization code mode to log in, first visit the address to obtain the authorization code: http://localhost:9201/oauth/authorize?response_type=code&client_id=client-app-2&redirect_uri=https://www.baidu.com

> 7. Visit the address and jump to the login page

![image](https://user-images.githubusercontent.com/35522446/111894879-78458600-8a49-11eb-9de8-05acf802c212.png)

> 8. After successful login, enter the authorization page

![image](https://user-images.githubusercontent.com/35522446/111894893-9a3f0880-8a49-11eb-90fd-432717e88ac5.png)

> 9. After authorization, get the authorization code

![image](https://user-images.githubusercontent.com/35522446/111894917-d6726900-8a49-11eb-9a78-0103ae6d2033.png)

> 10. Get the authorization code and access the address to log in: http://localhost:9201/oauth/token

![image](https://user-images.githubusercontent.com/35522446/111894933-fefa6300-8a49-11eb-8fd4-62c8ef9775f8.png)

> 11. Use the `user` account without access rights to log in. When accessing the interface, the following information will be returned, and the access address: http://localhost:9201/resource/hello

![image](https://user-images.githubusercontent.com/35522446/111894957-28b38a00-8a4a-11eb-8077-a159b8f6eef1.png)


## Project source code address
https://github.com/it-wwh/spring-cloud-gateway-oauth2
## the public
![image](https://user-images.githubusercontent.com/35522446/111441584-69f22400-8742-11eb-8ca6-617554f54605.png)
