package spring_boot.spring_security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping
public class HomeController {

    @GetMapping("/login")
    public String login(){
        return "member/login";
    }

    @GetMapping("/index")
    public String loginSuccess(){
        return "index";
    }
}
