package com.tchelo.auth_service.service.impl;

import com.tchelo.auth_service.entity.User;
import com.tchelo.auth_service.repository.UserRepository;
import com.tchelo.auth_service.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtServiceImpl implements JwtService {

    private final UserRepository userRepository;
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    public JwtServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public String generateTempToken(String phone) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "pre_mfa");
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(phone)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 300_000L)) // 5 min
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public String extractScope(String token) {
        try {
            return extractAllClaims(token).get("scope", String.class);
        } catch (Exception e) {
            return null;
        }
    }

    // Génère un JWT basé sur le numéro de téléphone
    @Override
    public String generateToken(String phone, UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        // Ajouter les rôles
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        User user = userRepository.findByPhone(phone).orElse(null);
        if (user != null && user.getStructureId() != null) {
            claims.put("structureId", user.getStructureId());
        }

        // Email transmis par la gateway (X-User-Email) aux services qui doivent écrire à l'utilisateur,
        // ex: ticket-service pour l'email de confirmation des billets
        if (user != null && user.getEmail() != null) {
            claims.put("email", user.getEmail());
        }

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(phone)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Création du token JWT
    private String createToken(Map<String, Object> claims, String phoneNumber) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(phoneNumber) // j'ai mis le numéro de téléphone en sujet.
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Extraction du numéro de téléphone depuis le token
    @Override
    public String extractPhoneNumber(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extraction générique d'une claim
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extraction de toutes les claims (avec vérification de signature)
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    public Long extractStructureId(String token) {
        Claims claims = extractAllClaims(token);
        Object structureIdObj = claims.get("structureId");

        if (structureIdObj == null) {
            return null;
        }

        if (structureIdObj instanceof Integer) {
            return ((Integer) structureIdObj).longValue();
        }

        if (structureIdObj instanceof Long) {
            return (Long) structureIdObj;
        }

        return null;
    }

    // Validation du token
    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        return !isTokenExpired(token);
    }

    // Vérifie l'expiration du token
    @Override
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extraction de la date d'expiration
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Génère la clé de signature
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
