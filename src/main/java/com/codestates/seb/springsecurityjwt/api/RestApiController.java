package com.codestates.seb.springsecurityjwt.api;

import com.codestates.seb.springsecurityjwt.member.Member;
import com.codestates.seb.springsecurityjwt.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/rest-home")
    public String home() {
        return "home";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody Member member) {

        member.setPassword(bCryptPasswordEncoder.encode(member.getPassword()));
        member.setRoles("ROLE_USER");
        memberRepository.save(member);

        return "회원가입완료";
    }

    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }
}
