package com.decathlon.security.demosecurity.config;

import static java.util.Collections.singletonList;

import com.fasterxml.classmate.TypeResolver;
import com.google.common.base.Predicates;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.UiConfiguration;
import springfox.documentation.swagger.web.UiConfigurationBuilder;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * Configure a {@link Docket} to integrate Swagger 2 in the project.
 * The Docket is configured to substitute Vavr object to Java object.
 */
@Configuration
@EnableSwagger2
@AllArgsConstructor(onConstructor = @__({@Autowired}))
public class SwaggerConfiguration {

  private static final String JWT_REFERENCE = "authkey";
  private TypeResolver typeResolver;

  /**
   * Internal Api without authentication
   */
  @Bean
  public Docket publicApi() {
    return
        new Docket(DocumentationType.SWAGGER_2)
            .groupName("publicApi")
            .select()
            .apis(RequestHandlerSelectors.any())
            .paths(PathSelectors.ant("/anonymous"))
            .build();
  }

  /**
   * Internal Api that needs authentication
   */
  @Bean
  public Docket privateApi() {
    return
        new Docket(DocumentationType.SWAGGER_2)
            .groupName("privateApi")
            .select()
            // Select Tesseract controller (to avoid Spring Boot auto-generated controller)
            .apis(RequestHandlerSelectors.basePackage("com.decathlon.security.demosecurity.controller"))
            .paths(Predicates.not(PathSelectors.ant("/authenticated")))
            .build()
            // Add a note on how to link JWT Bearer to requests
            .apiInfo(getApiInfo())
            // Automatically add JWT Authorization to requests header
            .securitySchemes(singletonList(getApiKey()))
            .securityContexts(singletonList(getSecurityContext()));
  }

  /**
   * Swagger UI configuration
   */
  @Bean
  public UiConfiguration uiConfig() {
    final String[] methodsWithTryItOutButton = {"get", "post", "put", "patch", "delete", "options"};
    return UiConfigurationBuilder
        .builder()
        .supportedSubmitMethods(methodsWithTryItOutButton)
        .build();
  }

  private static ApiInfo getApiInfo() {
    return new ApiInfoBuilder().title("Tesseract REST API")
        .description(
            "The REST API for Tesseract. \n\nNote: you can inject your JWT in every request by clicking on "
                + "\"Authorize\" on top right, then type as value \"Bearer &lt;JWT&gt;\".")
        .build();
  }

  private static SecurityContext getSecurityContext() {
    return SecurityContext.builder()
        .securityReferences(
            singletonList(SecurityReference.builder()
                .reference(JWT_REFERENCE)
                .scopes(new AuthorizationScope[0])
                .build()
            )
        )
        .build();
  }

  private static ApiKey getApiKey() {
    return new ApiKey(JWT_REFERENCE, "Authorization", "header");
  }

}
