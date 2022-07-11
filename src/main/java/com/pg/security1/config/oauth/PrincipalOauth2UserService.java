package com.pg.security1.config.oauth;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.pg.security1.config.auth.PrincipalDetails;
import com.pg.security1.config.oauth.provider.FacebookUserInfo;
import com.pg.security1.config.oauth.provider.GoogleUserInfo;
import com.pg.security1.config.oauth.provider.NaverUserInfo;
import com.pg.security1.config.oauth.provider.OAuth2UserInfo;
import com.pg.security1.model.User;
import com.pg.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService{
	
	@Autowired
	private UserRepository userRepository;
	
	private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
	
	 // 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
	// 함수 종료시 @authenticationPrincipal 어노테이션이 만들어진다.
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("getClientRegistration : " + userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인 했는지 확인가능.
		System.out.println("getAccessToken : " + userRequest.getAccessToken().getTokenValue());
		System.out.println("loadUser : " + super.loadUser(userRequest).getAttributes()); 
		// 구글로그인 버튼 클릭 -> 구글로그인 창 -> 로그인을 완료 -> code를 리턴(Oauth-client라이브러리) -> AccessToken요청
		// userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원프로필 받아준다.
		// username = google_sub값, password = "암호화(dante)", email = "email값", role = "ROLE_USER", provider = "google", prviderId = sub값
		
		OAuth2User oauth2User = super.loadUser(userRequest);
		System.out.println("getAttributes : " + oauth2User.getAttributes());
		
		
		OAuth2UserInfo oAuth2UserInfo = null;
		if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
		}else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
			System.out.println("페이스북 로그인 요청");
			oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
		}else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
			System.out.println("네이버 로그인 요청");
			oAuth2UserInfo = new NaverUserInfo((Map)oauth2User.getAttributes().get("response"));
		}else {
			System.out.println("구글 , 페이스북 네이버만 지원");
		}
		
		//String provider = userRequest.getClientRegistration().getRegistrationId(); //google
		String provider = oAuth2UserInfo.getProvider();
		
		//String providerId = oauth2User.getAttribute("sub");
		String providerId = oAuth2UserInfo.getProviderId();
		
		String username = provider+"_"+providerId; // google_provider
		String password = bCryptPasswordEncoder.encode("dante");
		//String email = oauth2User.getAttribute("email");
		String email = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";
		
		User userEntity = userRepository.findByUsername(username);
		
		if(userEntity == null) {
			System.out.println("소셜로그인이 최초입니다.");
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			
			userRepository.save(userEntity);
		}else {
			System.out.println("로그인을 이미 한적이 있습니다. 자동회원가입이 되어 있습니다.");
		}
		
		
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
