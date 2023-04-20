package com.toyproject.bookmanagement.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.toyproject.bookmanagement.entity.Authority;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;

@Builder
@Getter
@Data
public class PrincipalUserDetails implements UserDetails {

	private int userId;
	private String email;
	private String password;
	private List<Authority> authorities;
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		List<SimpleGrantedAuthority> authorities = new ArrayList<>();
		this.authorities.forEach(authority -> {
			authorities.add(new SimpleGrantedAuthority(authority.getRole().getRoleName()));
		});
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return email;
	}

	//사용기간 만료
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}
	
	// 계정을 잠궈버림
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}
	
	//비밀번호 5회 틀렸을 때 잠김
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	
	//계정 비활성 상태(이메일 인증을 완료하거나, 전화번호 인증을 하지 않았을 때)
	@Override
	public boolean isEnabled() {
		return true;
	}
	
}
