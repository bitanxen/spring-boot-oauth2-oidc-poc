package in.bitanxen.poc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping("/")
public class LoginController {

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String getLoginPage() {
        return "login";
    }

    /*
    @RequestMapping(value = "/authorize", method = RequestMethod.GET)
    public String getAuthorizePage() {
        return "authorize";
    }

     */
}
