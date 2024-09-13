package com.security.Jwt.Authentication.Security.webtoken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.springframework.cache.interceptor.SimpleKeyGenerator.generateKey;
@Service
public class JwtService {
 private static final String SECRET = "1E6480E6758E3A9041E4C3D57D93C3B658B968B8A1DEC76B83BBCA9F1BB63BD9E53136549BF6B5C83A5C4E5A2B882EC954A52EB6318D93DBF471ACAC00882FA1";
 public static final long VALIDITY = TimeUnit.MINUTES.toMillis(30);

 public String generateToken(UserDetails userDetails){
  Map<String, String> claims = new HashMap<>();
  claims.put("iss", "https://secure.genuinecoder.com");
//  claims.put("name", "bruce");
   return Jwts.builder()
          .claims(claims)
          .subject(userDetails.getUsername())
          .issuedAt(Date.from(Instant.now()))
          .expiration(Date.from(Instant.now().plusMillis(VALIDITY)))
          .signWith(generateKey())
          .compact();
 }

 private SecretKey generateKey(){
  byte[] decodekey = Base64.getDecoder().decode(SECRET);
  return Keys.hmacShaKeyFor(decodekey);
 }

 public String extractUsername(String jwt) {
  Claims claims = getClaims(jwt);
  return claims.getSubject();
 }
     private Claims getClaims(String jwt){
      Claims claims = Jwts.parser()
             .verifyWith(generateKey())
             .build()
             .parseSignedClaims(jwt)
             .getPayload();
     return claims;
 }

 public boolean isTokenValid(String jwt) {
  Claims claims = getClaims(jwt);
  return claims.getExpiration().after(Date.from(Instant.now()));
 }
}
