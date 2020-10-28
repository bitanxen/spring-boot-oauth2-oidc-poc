package in.bitanxen.poc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class IndexController {

    @RequestMapping(value = {"/", "index"})
    public String getIndex() {
        return "index";
    }
}
