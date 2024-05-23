package com.example.demo.Service;

import com.example.demo.Model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY = "6229cdf9df77730d37b377e43bdc7f04d5c6c5ce2a8d4fa60c69e76a53e6ed19";


    // extracting user name frp=om claims
    public String extractUserName(String token){
        return extractClaim(token, Claims::getSubject);
    }


    // checking is token is valid (usename of token is equal to username in userDetails)
    public boolean isValid(String token, UserDetails user){
        String username = extractUserName(token);
        return (username.equals(user.getUsername()) && !isTokenExpired(token));
    }

    // is token Expired
    private boolean isTokenExpired(String token) {
     return ExtractExpiration(token).before(new Date());
    }

    // ExpirationDate
    private  Date ExtractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }




    // Extracting Specific property from payload
    public <T> T extractClaim(String token, Function<Claims,T> resolver){
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }



    // Extract all payload/claims from token
    private Claims extractAllClaims(String token){
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    public String generateToke(User user){

        String token  = Jwts.builder()
                .subject(user.getUsername())
                .issuedAt( new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
                .signWith( getSignInKey())
                .compact();

        return token;
    }

    private SecretKey getSignInKey(){
        byte[] Keybytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(Keybytes);

    }
}
