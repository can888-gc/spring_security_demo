package com.imooc.uua.res;

import lombok.Data;
import lombok.ToString;
import org.springframework.web.bind.annotation.*;

/**
 * @author mCarr
 */
@RestController
@RequestMapping("/api")
public class UserResource {

    @GetMapping("/greeting")
    public String greeting(){
        return "Hello World";
    }

    @PostMapping("/greeting")
    public String makeGreeting(@RequestParam String name,@RequestBody Profile profile){
        return "Hello World " + name + "\n" + profile.toString();
    }

    @PutMapping("/greeting/{name}")
    public String putGreeting(@PathVariable String name){
        return "Hello World " + name;
    }

    @ToString
    @Data
    static class Profile{
        private String gender;
        private String idNo;

    }

}
