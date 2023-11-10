package org.sid.ebankingbackend.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

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
                // tt rqt necessite authentification
                .authorizeHttpRequests(ar->ar.anyRequest().authenticated())
                // type auth , form login ou httpBasic ( une fenetre comme celle du js notif)
                // Basic auth : GET http://localhost:8085/customers Accept: application/json Authorization: Basic user1:12345
                .httpBasic(Customizer.withDefaults())
                .build();
    }
}
