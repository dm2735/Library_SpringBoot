package com.toyproject.bookmanagement.service;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.toyproject.bookmanagement.dto.auth.JwtTokenRespDto;
import com.toyproject.bookmanagement.dto.auth.LoginReqDto;
import com.toyproject.bookmanagement.dto.auth.SignupReqDto;
import com.toyproject.bookmanagement.entity.Authority;
import com.toyproject.bookmanagement.entity.User;
import com.toyproject.bookmanagement.exception.CustomException;
import com.toyproject.bookmanagement.exception.ErrorMap;
import com.toyproject.bookmanagement.repository.UserRepository;
import com.toyproject.bookmanagement.security.JwtTokenProvider;

import lombok.RequiredArgsConstructor;


@Service
@RequiredArgsConstructor
public class AuthenticationService implements UserDetailsService {
	
	private final UserRepository userRepository;
	private final AuthenticationManagerBuilder authenticationManagerBuilder;
	private final JwtTokenProvider jwtTokenProvider;

	
	public void duplicatedEmail(String email) {
		
		if(userRepository.findUserByEmail(email) != null) {
			 throw new CustomException("duplicatedEmail", 
					 ErrorMap.builder().put("email", "이미 사용중인 이메일입니다.").build());
		}
	}
	
	public void signup(SignupReqDto signupReqDto) {
		User userEntity = signupReqDto.toEntity();
		userRepository.saveUser(userEntity);
		
		userRepository.saveAuthority(Authority.builder().userId(userEntity.getUserId()).roleId(1).build());
		}
	
	
	public JwtTokenRespDto login(LoginReqDto loginReqDto) {
		
		UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(loginReqDto.getEmail(), loginReqDto.getPassword());
		
		Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
		
		return jwtTokenProvider.createToken(authentication);
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		
		User userEntity = userRepository.findUserByEmail(email);
		System.out.println(userEntity);
		if (userEntity == null) {
			throw new CustomException("로그인 실패", ErrorMap.builder().put("email", "사용자 정보를 확인하세요.").build());
		}
		
		return userEntity.toPrincipal();
	}
	
	
}	