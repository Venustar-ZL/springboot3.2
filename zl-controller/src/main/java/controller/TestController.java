package controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * ClassName: TestController.
 * Description:
 * date: 2023/12/28 21:49
 *
 * @author ZhangLei
 */
@Slf4j
@RestController
@Tag(name = "Test", description = "Test")
@RequestMapping("/v1/test")
public class TestController {

    @Operation(summary = "Test", description = "测试")
    @PostMapping(value = "/get")
    public void get() {

        log.info("test");

    }

}
