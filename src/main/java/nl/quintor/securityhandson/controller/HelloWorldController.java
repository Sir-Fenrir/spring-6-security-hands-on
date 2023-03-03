package nl.quintor.securityhandson.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

    @GetMapping("/hello_world")
    public String helloWorld() {
        return "Hello World!";
    }

    @GetMapping("/hello_universe")
    public String helloUniverse() {
        return "Hello Universe!";
    }

}
