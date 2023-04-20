package com.toyproject.bookmanagement.security;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.toyproject.bookmanagement.dto.auth.JwtTokenRespDto;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtTokenProvider {
	
	private final Key key;
	
	public JwtTokenProvider(@Value("${jwt.secretKey}") String secretKey) {
		key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
	}
	
	public JwtTokenRespDto createToken(Authentication authentication) {
		StringBuilder authoritiesBuilder = new StringBuilder();
		
		authentication.getAuthorities().forEach(authority -> {
			authoritiesBuilder.append(authority.getAuthority() + ",");
		});
			authoritiesBuilder.delete(authoritiesBuilder.length()-1, authoritiesBuilder.length());
			
			String authorities = authoritiesBuilder.toString();
			
			long now = new Date().getTime();

		      Date tokenExpiresDate = new Date(now + (1000 * 60 * 60 * 24)) ; 
		      		      
		      
		      String accessToken = Jwts.builder()
		            .setSubject(authentication.getName())
		            .claim("auth", authorities)
		            .setExpiration(tokenExpiresDate)
		            .signWith(key, SignatureAlgorithm.HS256)
		            .compact();
			
					
		return JwtTokenRespDto.builder()
				.grantType("Bearer")
				.accessToken(accessToken)
				.build();
	}
}
