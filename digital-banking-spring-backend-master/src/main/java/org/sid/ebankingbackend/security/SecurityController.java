package org.sid.ebankingbackend.security;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class SecurityController {

    @Autowired // pour faire l'authentification de user et lui generer un token apres
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtEncoder jwtEncoder;


    // rturn le user : GET http://localhost:8085/auth/profile Authorization: Basic dXNlcjE6MTIzNDU=
    @GetMapping("/profile")
    public Authentication authentication(Authentication authentication){
        return authentication ;
    }

    @PostMapping("/login")
    public Map<String,String> login (String username , String pasword){

        // il va utiliser le bean AuthenticationManager pour l'auth
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, pasword));

        //generer le JWT
        Instant instant= Instant.now();
        String scope = authentication.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.joining(" "));// recuperer les roles de user separer par " "
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuedAt(instant) // date genration
                .expiresAt(instant.plus(10, ChronoUnit.MINUTES)) // date expiration , 10 min apres
                .subject(username)
                .claim("scope",scope) // les roles de user
                .build();


        //signer le token
        JwtEncoderParameters jwtEncoderParameters=
                JwtEncoderParameters.from(
                                JwsHeader.with(MacAlgorithm.HS512).build(),jwtClaimsSet // ON PEUT VOIR QUE DANS LA SIGNATURE EN ENCODE LE HEADER ET LE PAYLOAD
                        );


        String jwt = jwtEncoder.encode(jwtEncoderParameters).getTokenValue(); // ON CODE AVEC LE SECRET


        return Map.of("access-token",jwt);

    }

}
