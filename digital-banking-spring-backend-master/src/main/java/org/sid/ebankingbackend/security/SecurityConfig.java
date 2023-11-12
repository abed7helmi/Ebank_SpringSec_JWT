package org.sid.ebankingbackend.security;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // gestion des roles dans les Get et Post , 2éme etape ,  les controlleurs
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String secretKey ;


    /* InMemoryUserDetailsManager : pour stocker les informations d'authentification des utilisateurs en mémoire, ce qui est utile
    pour les applications de développement ou de test où vous ne souhaitez pas configurer une base de données d'utilisateurs.*/



    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        PasswordEncoder passwordEncoder = passwordEncoder();
        return new InMemoryUserDetailsManager(
                /*User.withUsername("user1").password("12345").authorities("USER").build(),
                User.withUsername("admin").password("12345").authorities("USER","ADMIN").build()*/
                User.withUsername("user1").password(passwordEncoder.encode("12345")).authorities("USER").build(),
                User.withUsername("admin").password(passwordEncoder.encode("12345")).authorities("USER","ADMIN").build()
        );

    }
    /* PasswordEncoder: utilisée pour encoder les mots de passe., BcryptPass  est une implémentation de l'interface PasswordEncoder qui utilise l'algorithme de hachage BCrypt*/

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // pour protegre l'appli il faut creer des filtres
    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                //stateless
                .sessionManagement(sm->sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // desactiver la protection csrf / une mesure de sécurité mise en place pour prévenir les attaques dans lesquelles un attaquant exploite la confiance d'un utilisateur authentifié afin d'induire ce dernier à effectuer involontairement des actions indésirables
                .csrf(crsf-> crsf.disable())
                // authorize la rqt d'auth de n a pas avoir les login 'authentification
                .authorizeHttpRequests(ar->ar.requestMatchers("/auth/login/**").permitAll())
                // tt rqt necessite authentification
                .authorizeHttpRequests(ar->ar.anyRequest().authenticated())
                // type auth , form login ou httpBasic ( une fenetre comme celle du js notif)
                // Basic auth : GET http://localhost:8085/customers Accept: application/json Authorization: Basic user1:12345
                //.httpBasic(Customizer.withDefaults()) : pour etuliser la methode BASIC

                //pour utiliser la methode JWT
                .oauth2ResourceServer(oa -> oa.jwt(Customizer.withDefaults()))
                .build();
    }

    // pour trvailler avec JWT , il faut avoir deux bean jwtEncoder (generte et signe les tkns) et JWTDecoder (intercepte la rqt et verifier la signature pour l'auth)


    // pour un encoder , je doit avoir un secret
    @Bean
    JwtEncoder jwtEncoder(){
        //String secretKey="1azblmh6701kkbl231701azblmh6701amlqmh6701azblmh6701azblmh6701azw";
        return new NimbusJwtEncoder(new ImmutableSecret<>(secretKey.getBytes()));
    }

    @Bean
    JwtDecoder jwtDecoder(){
        //String secretKey="1azblmh6701kkbl231701azblmh6701amlqmh6701azblmh6701azblmh6701azw";
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes() , "RSA");
        return NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm(MacAlgorithm.HS512).build();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder()); // comparer les mdp
        daoAuthenticationProvider.setUserDetailsService(userDetailsService); // userDetailsService == InMemoryUserDetailsManager
        return new ProviderManager(daoAuthenticationProvider);
    }
}
